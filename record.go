package passkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"

	"filippo.io/mldsa"
	"filippo.io/passkey/internal/ctap2cbor"
)

type record struct {
	transports   []string
	rpIDHash     [32]byte
	flags        flags
	aaguid       [16]byte
	credentialID []byte
	key          crypto.PublicKey
}

func parseRecord(r string) (*record, error) {
	r, ok := strings.CutPrefix(r, "$webauthn$v=1$")
	if !ok {
		return nil, errors.New("passkey: invalid record")
	}
	rr := &record{}
	var params string
	if p, rest, ok := strings.Cut(r, "$"); ok {
		params, r = p, rest
	}
	for len(params) > 0 {
		var kv string
		kv, params, ok = strings.Cut(params, ",")
		if ok && params == "" {
			return nil, errors.New("passkey: invalid record: invalid parameters")
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, errors.New("passkey: invalid record: invalid parameters")
		}
		if k != "transports" {
			continue
		}
		if rr.transports != nil {
			return nil, errors.New("passkey: invalid record: duplicate transports parameter")
		}
		rr.transports = strings.Split(v, "+")
		for i, t := range rr.transports {
			if !validTransport(t) {
				return nil, fmt.Errorf("passkey: invalid record: invalid transport %q", t)
			}
			if i > 0 && rr.transports[i-1] >= t {
				return nil, errors.New("passkey: invalid record: transports are not sorted and deduplicated")
			}
		}
	}
	if strings.ContainsAny(r, "\r\n") {
		return nil, errors.New("passkey: invalid record")
	}
	ad, err := base64.RawStdEncoding.Strict().DecodeString(r)
	if err != nil {
		return nil, fmt.Errorf("passkey: invalid record: %w", err)
	}
	if err := parseRegistrationAuthData(rr, ad); err != nil {
		return nil, fmt.Errorf("passkey: invalid record: %w", err)
	}
	return rr, nil
}

type flags uint8

// Authenticator data flags, from WebAuthn §6.1.
func (f flags) userPresent() bool    { return f&(1<<0) != 0 }
func (f flags) userVerified() bool   { return f&(1<<2) != 0 }
func (f flags) backupEligible() bool { return f&(1<<3) != 0 }
func (f flags) backupState() bool    { return f&(1<<4) != 0 }
func (f flags) attestedData() bool   { return f&(1<<6) != 0 }
func (f flags) extensionData() bool  { return f&(1<<7) != 0 }

func parseRegistrationAuthData(r *record, b []byte) error {
	if len(b) < 55 {
		return fmt.Errorf("authenticator data is %d bytes, expected at least 55", len(b))
	}

	copy(r.rpIDHash[:], b[:32])
	b = b[32:]

	r.flags = flags(b[0])
	if !r.flags.attestedData() {
		return errors.New("authenticator data has no attested credential data")
	}
	if r.flags.backupState() && !r.flags.backupEligible() {
		return errors.New("credential is backed up but not backup eligible")
	}
	b = b[1:]

	b = b[4:] // sign count

	copy(r.aaguid[:], b[:16])
	b = b[16:]

	length := binary.BigEndian.Uint16(b[:2])
	if length < 16 || length > 1023 {
		return fmt.Errorf("credential ID is %d bytes, expected between %d and %d", length, 16, 1023)
	}
	b = b[2:]
	if len(b) < int(length) {
		return errors.New("authenticator data is too short for the credential ID")
	}
	r.credentialID = b[:length]
	b = b[length:]

	// The COSE key has no length prefix: its extent is discovered by
	// parsing it, which leaves the cursor at the extension data, if any.
	key, b, err := parseCOSEKey(b)
	if err != nil {
		return err
	}
	r.key = key

	if r.flags.extensionData() {
		if len(b) == 0 {
			return errors.New("authenticator data claims extension data but has none")
		}
	} else {
		if len(b) != 0 {
			return fmt.Errorf("authenticator data has %d unexpected trailing bytes", len(b))
		}
	}

	return nil
}

// COSE key types, from the IANA COSE Key Types registry.
const (
	coseKeyTypeEC2 = 2
	coseKeyTypeRSA = 3
	coseKeyTypeAKP = 7
)

// COSE algorithm identifiers, from the IANA COSE Algorithms registry.
const (
	algES256      = -7
	coseCurveP256 = 1
	algRS256      = -257
	algMLDSA44    = -48
	algMLDSA65    = -49
	algMLDSA87    = -50
)

func parseCOSEKey(b []byte) (crypto.PublicKey, []byte, error) {
	s := ctap2cbor.String(b)
	var pairs uint16
	if !s.ReadMapHeader(&pairs) {
		return nil, nil, errors.New("malformed COSE key: bad map header")
	}

	// Map keys must be unique and in CTAP2 canonical order. Because that order
	// places the kty label (1) and the alg label (3) before every negative label,
	// the meaning of the algorithm-specific labels is known by the time they come.

	var label, kty int16
	if !s.ReadInt(&label) || label != 1 || !s.ReadInt(&kty) {
		return nil, nil, errors.New("malformed COSE key: bad kty")
	}
	var alg int16
	if !s.ReadInt(&label) || label != 3 || !s.ReadInt(&alg) {
		return nil, nil, errors.New("malformed COSE key: bad alg")
	}
	switch kty {
	case coseKeyTypeEC2:
		if pairs != 5 {
			return nil, nil, errors.New("malformed COSE key: bad map length")
		}
		if alg != algES256 {
			return nil, nil, fmt.Errorf("unsupported COSE algorithm %d for EC2 key", alg)
		}
		var crv int16
		if !s.ReadInt(&label) || label != -1 || !s.ReadInt(&crv) || crv != coseCurveP256 {
			return nil, nil, errors.New("malformed COSE key: bad crv")
		}
		var x, y []byte
		if !s.ReadInt(&label) || label != -2 || !s.ReadBytes(&x) || len(x) != 32 {
			return nil, nil, errors.New("malformed COSE key: bad x")
		}
		if !s.ReadInt(&label) || label != -3 || !s.ReadBytes(&y) || len(y) != 32 {
			return nil, nil, errors.New("malformed COSE key: bad y")
		}
		point := make([]byte, 0, 65)
		point = append(point, 4)
		point = append(point, x...)
		point = append(point, y...)
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			return nil, nil, errors.New("malformed COSE key: invalid P-256 public key")
		}
		return key, []byte(s), nil
	case coseKeyTypeRSA:
		if pairs != 4 {
			return nil, nil, errors.New("malformed COSE key: bad map length")
		}
		if alg != algRS256 {
			return nil, nil, fmt.Errorf("unsupported COSE algorithm %d for RSA key", alg)
		}
		var n []byte
		if !s.ReadInt(&label) || label != -1 || !s.ReadBytes(&n) || len(n) == 0 || n[0] == 0 {
			return nil, nil, errors.New("malformed COSE key: bad RSA modulus")
		}
		modulus := new(big.Int).SetBytes(n)
		if bits := modulus.BitLen(); bits < 2048 || bits > 4096 {
			return nil, nil, fmt.Errorf("unsupported RSA modulus size: %d bits", bits)
		}
		var e []byte
		if !s.ReadInt(&label) || label != -2 || !s.ReadBytes(&e) || len(e) == 0 || len(e) > 4 || e[0] == 0 {
			return nil, nil, errors.New("malformed COSE key: bad RSA exponent")
		}
		exponent := new(big.Int).SetBytes(e).Int64()
		if exponent < 3 || exponent > math.MaxInt32 || exponent%2 == 0 {
			return nil, nil, errors.New("malformed COSE key: invalid RSA public exponent")
		}
		return &rsa.PublicKey{N: modulus, E: int(exponent)}, []byte(s), nil
	case coseKeyTypeAKP:
		if pairs != 3 {
			return nil, nil, errors.New("malformed COSE key: bad map length")
		}
		var params *mldsa.Parameters
		switch alg {
		case algMLDSA44:
			params = mldsa.MLDSA44()
		case algMLDSA65:
			params = mldsa.MLDSA65()
		case algMLDSA87:
			params = mldsa.MLDSA87()
		default:
			return nil, nil, fmt.Errorf("unsupported COSE algorithm %d for AKP key", alg)
		}
		var pub []byte
		if !s.ReadInt(&label) || label != -1 || !s.ReadBytes(&pub) {
			return nil, nil, errors.New("malformed COSE key: bad public key")
		}
		if len(pub) != params.PublicKeySize() {
			return nil, nil, fmt.Errorf("malformed COSE key: %s public key must be %d bytes, got %d",
				params, params.PublicKeySize(), len(pub))
		}
		key, err := mldsa.NewPublicKey(params, pub)
		if err != nil {
			return nil, nil, fmt.Errorf("malformed COSE key: invalid %s public key", params)
		}
		return key, []byte(s), nil
	default:
		return nil, nil, fmt.Errorf("unsupported COSE key type %d", kty)
	}
}

func encodeRecord(authenticatorData []byte, transports []string) string {
	var sb strings.Builder
	sb.WriteString("$webauthn$v=1$")
	if len(transports) > 0 {
		sb.WriteString("transports=")
		sb.WriteString(strings.Join(transports, "+"))
		sb.WriteString("$")
	}
	sb.WriteString(base64.RawStdEncoding.EncodeToString(authenticatorData))
	return sb.String()
}

// AAGUID returns the authenticator's AAGUID from a passkey record, which
// may identify the passkey provider (e.g. for display purposes, using
// the community-maintained AAGUID lists). It is all zeroes if the
// authenticator did not provide one.
func AAGUID(passkey string) ([16]byte, error) {
	r, err := parseRecord(passkey)
	if err != nil {
		return [16]byte{}, err
	}
	return r.aaguid, nil
}

// BackedUp reports whether the credential was backed up (e.g. synced to
// a cloud account) at registration time. For the current state, check
// login responses with [Response.BackedUp].
func BackedUp(passkey string) (bool, error) {
	r, err := parseRecord(passkey)
	if err != nil {
		return false, err
	}
	return r.flags.backupState(), nil
}

// Transports returns the transport hints recorded at registration
// (e.g. "internal", "hybrid", "usb"). They are used to populate the
// credential descriptors sent to clients by
// [RelyingParty.NewRegistration] and [RelyingParty.NewLoginForUser],
// where they help the client reach the right authenticator during
// login; they are exposed for interoperability and diagnostics.
func Transports(passkey string) ([]string, error) {
	r, err := parseRecord(passkey)
	if err != nil {
		return nil, err
	}
	return r.transports, nil
}

// credentialDescriptor is the client-side description of a credential, used
// for both excludeCredentials and allowCredentials.
type credentialDescriptor struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

// credentialDescriptors converts passkey records into credential descriptors,
// failing if any record is malformed.
func credentialDescriptors(passkeys []string) ([]credentialDescriptor, error) {
	out := make([]credentialDescriptor, 0, len(passkeys))
	for i, p := range passkeys {
		r, err := parseRecord(p)
		if err != nil {
			return nil, fmt.Errorf("passkey record %d: %w", i, err)
		}
		out = append(out, credentialDescriptor{
			Type:       "public-key",
			ID:         base64.RawURLEncoding.EncodeToString(r.credentialID),
			Transports: r.transports,
		})
	}
	return out, nil
}
