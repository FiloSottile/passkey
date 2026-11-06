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
	recordMetadata
	key crypto.PublicKey
}

type recordMetadata struct {
	transports   []string
	rpIDHash     [32]byte
	flags        flags
	aaguid       [16]byte
	credentialID []byte
}

func parseRecord(r string) (*record, error) {
	rr := &record{}
	r, err := parseRecordParams(&rr.recordMetadata, r)
	if err != nil {
		return nil, err
	}
	ad, err := base64.RawStdEncoding.Strict().DecodeString(r)
	if err != nil {
		return nil, fmt.Errorf("passkey: invalid record: %w", err)
	}
	// The decoder skips newlines, which shortens the output.
	if base64.RawStdEncoding.EncodedLen(len(ad)) != len(r) {
		return nil, errors.New("passkey: invalid record")
	}
	if err := parseRegistrationAuthData(rr, ad); err != nil {
		return nil, fmt.Errorf("passkey: invalid record: %w", err)
	}
	return rr, nil
}

// parseRecordMetadata is like parseRecord, but it skips the credential
// public key, and decodes only the start of the authenticator data.
// It may accept some records that parseRecord rejects.
func parseRecordMetadata(r string) (*recordMetadata, error) {
	m := &recordMetadata{}
	r, err := parseRecordParams(m, r)
	if err != nil {
		return nil, err
	}
	ad, err := decodeRecordPrefix(r, authDataHeaderLen)
	if err != nil {
		return nil, err
	}
	if len(ad) >= authDataHeaderLen {
		length := binary.BigEndian.Uint16(ad[authDataHeaderLen-2:])
		ad, err = decodeRecordPrefix(r, authDataHeaderLen+int(length))
		if err != nil {
			return nil, err
		}
	}
	if _, err := parseAuthDataMetadata(m, ad); err != nil {
		return nil, fmt.Errorf("passkey: invalid record: %w", err)
	}
	return m, nil
}

// authDataHeaderLen is the length of the authenticator data
// up to the credential ID.
const authDataHeaderLen = 55

// decodeRecordPrefix decodes at least the first n bytes of the base64
// authenticator data r, or all of it if shorter.
func decodeRecordPrefix(r string, n int) ([]byte, error) {
	// The padded length is a whole number of 4-character quanta.
	r = r[:min(base64.StdEncoding.EncodedLen(n), len(r))]
	ad, err := base64.RawStdEncoding.Strict().DecodeString(r)
	if err != nil {
		return nil, fmt.Errorf("passkey: invalid record: %w", err)
	}
	// The decoder skips newlines, which shortens the output.
	if base64.RawStdEncoding.EncodedLen(len(ad)) != len(r) {
		return nil, errors.New("passkey: invalid record")
	}
	return ad, nil
}

// parseRecordParams parses the PHC String prefix and parameters of a
// record into m, and returns the encoded authenticator data.
func parseRecordParams(m *recordMetadata, r string) (string, error) {
	r, ok := strings.CutPrefix(r, "$webauthn$v=1$")
	if !ok {
		return "", errors.New("passkey: invalid record")
	}
	var params string
	if p, rest, ok := strings.Cut(r, "$"); ok {
		if p == "" {
			return "", errors.New("passkey: invalid record: invalid parameters")
		}
		params, r = p, rest
	}
	for len(params) > 0 {
		var kv string
		kv, params, ok = strings.Cut(params, ",")
		if ok && params == "" {
			return "", errors.New("passkey: invalid record: invalid parameters")
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !validParamName(k) || !validParamValue(v) {
			return "", errors.New("passkey: invalid record: invalid parameters")
		}
		if k != "transports" {
			continue
		}
		if m.transports != nil {
			return "", errors.New("passkey: invalid record: duplicate transports parameter")
		}
		m.transports = strings.Split(v, "+")
		if len(m.transports) > 32 {
			return "", errors.New("passkey: invalid record: too many transports")
		}
		for i, t := range m.transports {
			if !validTransport(t) {
				return "", fmt.Errorf("passkey: invalid record: invalid transport %q", t)
			}
			if i > 0 && m.transports[i-1] >= t {
				return "", errors.New("passkey: invalid record: transports are not sorted and deduplicated")
			}
		}
	}
	return r, nil
}

// validParamName reports whether k is a PHC String parameter name:
// [a-z0-9-]{1,32}, excluding "v" which is reserved for the version field.
// See https://c2sp.org/phc-strings.
func validParamName(k string) bool {
	if k == "" || len(k) > 32 || k == "v" {
		return false
	}
	for _, c := range k {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// validParamValue reports whether v is a PHC String parameter value:
// [a-zA-Z0-9/+.-]*. See https://c2sp.org/phc-strings.
func validParamValue(v string) bool {
	for _, c := range v {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '+', c == '-', c == '.', c == '/':
		default:
			return false
		}
	}
	return true
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
	if len(b) > 8192 {
		return fmt.Errorf("authenticator data is %d bytes, expected at most 8192", len(b))
	}
	b, err := parseAuthDataMetadata(&r.recordMetadata, b)
	if err != nil {
		return err
	}

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

// parseAuthDataMetadata parses the authenticator data up to the credential
// public key into r, and returns the rest.
func parseAuthDataMetadata(r *recordMetadata, b []byte) ([]byte, error) {
	if len(b) < authDataHeaderLen {
		return nil, fmt.Errorf("authenticator data is %d bytes, expected at least 55", len(b))
	}

	copy(r.rpIDHash[:], b[:32])
	b = b[32:]

	r.flags = flags(b[0])
	if !r.flags.attestedData() {
		return nil, errors.New("authenticator data has no attested credential data")
	}
	if r.flags.backupState() && !r.flags.backupEligible() {
		return nil, errors.New("credential is backed up but not backup eligible")
	}
	b = b[1:]

	b = b[4:] // sign count

	copy(r.aaguid[:], b[:16])
	b = b[16:]

	length := binary.BigEndian.Uint16(b[:2])
	if length < 16 || length > 1023 {
		return nil, fmt.Errorf("credential ID is %d bytes, expected between %d and %d", length, 16, 1023)
	}
	b = b[2:]
	if len(b) < int(length) {
		return nil, errors.New("authenticator data is too short for the credential ID")
	}
	r.credentialID = b[:length]
	return b[length:], nil
}

// ErrUnsupportedAlgorithm is returned by [RelyingParty.Register] when a
// credential has a public key type that this package does not support.
//
// It is always wrapped, so callers must use [errors.Is].
var ErrUnsupportedAlgorithm = errors.New("unsupported credential public key algorithm")

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
			return nil, nil, fmt.Errorf("%w (COSE algorithm %d for EC2 key)", ErrUnsupportedAlgorithm, alg)
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
			return nil, nil, fmt.Errorf("%w (COSE algorithm %d for RSA key)", ErrUnsupportedAlgorithm, alg)
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
		var params mldsa.Parameters
		switch alg {
		case algMLDSA44:
			params = mldsa.MLDSA44()
		default:
			return nil, nil, fmt.Errorf("%w (COSE algorithm %d for AKP key)", ErrUnsupportedAlgorithm, alg)
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
		return nil, nil, fmt.Errorf("%w (COSE key type %d)", ErrUnsupportedAlgorithm, kty)
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
	r, err := parseRecordMetadata(passkey)
	if err != nil {
		return [16]byte{}, err
	}
	return r.aaguid, nil
}

func userVerificationAvailable(r *record) bool {
	// WebAuthn L3, Section 4 (see uvInitialized) insists that the UV
	// flag can be relied upon only if the credential was previously
	// observed with UV in a trusted context, either at registration or
	// during a login with an additional factor.
	//
	// The reason is to prevent an attack where an authenticator did not
	// have UV at registration, and then the attacker steals it and
	// configures their own PIN.
	//
	// The problem with this is that 1. it would require storing a
	// separate mutable boolean per record, or updating the record upon
	// (certain) logins, and 2. it defeats the point of UV-less
	// conditional registration. (If a UV+password login is required to
	// "upgrade" the record to a passwordless credential, then you might
	// as well just forgo conditional registration.)
	//
	// Ideally, a credProps field would be introduced to communicate
	// what actually matters for security: whether the authenticator has
	// UV *set up*, not whether UV was obtained during registration.
	//
	// In the meantime, we can trust UV for credentials generated with
	// conditional registration (which is not supported by external
	// authenticators), and we can reliably detect them: conditional
	// creation is the only one that can omit the UP flag (Section 6.3.2,
	// requireUserPresence).
	//
	// userVerificationAvailable is false only for imported records:
	// [RelyingParty.Register] refuses to produce one, and should only
	// encounter one if an application uses conditional options in a
	// non-conditional registration by mistake, because our regular
	// options require UV at registration.
	//
	// See https://go.dev/issue/80663.
	return r.flags.userVerified() || !r.flags.userPresent()
}

// credentialDescriptor is the client-side description of a credential, used
// for both excludeCredentials and allowCredentials.
type credentialDescriptor struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

// credentialDescriptors converts passkey records into credential descriptors..
func credentialDescriptors(passkeys []string) []credentialDescriptor {
	out := make([]credentialDescriptor, 0, len(passkeys))
	for _, p := range passkeys {
		r, err := parseRecordMetadata(p)
		if err != nil {
			// For excludeCredentials/allowCredentials it's ok to drop malformed records.
			continue
		}
		out = append(out, credentialDescriptor{
			Type:       "public-key",
			ID:         base64.RawURLEncoding.EncodeToString(r.credentialID),
			Transports: r.transports,
		})
	}
	return out
}
