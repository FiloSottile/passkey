package passkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"maps"
	"sync"
	"testing"

	"filippo.io/mldsa"
)

// Authenticator data flags, from WebAuthn §6.1.
const (
	flagUP byte = 1 << 0
	flagUV byte = 1 << 2
	flagBE byte = 1 << 3
	flagBS byte = 1 << 4
	flagAT byte = 1 << 6
	flagED byte = 1 << 7
)

// AKP COSE algorithms that newAuthenticator can generate credentials for
// but this package does not support, from draft-ietf-cose-dilithium.
const (
	algMLDSA65 = -49
	algMLDSA87 = -50
)

// authenticator is a software authenticator, and enough of the client
// around it to run complete registration and login ceremonies against
// this package without a browser.
//
// Responses are assembled and signed by the response methods, so tests
// can override any field after construction and obtain a fresh
// (re-signed, where the protocol signs it) response.
type authenticator struct {
	aaguid       [16]byte
	credentialID []byte
	alg          int32
	coseKey      []byte
	transports   []string

	// extensions, if non-empty, is appended to the authenticator data as
	// authenticator extension outputs, and the ED flag is set.
	extensions []byte

	// clientDataType, if non-empty, overrides the client data type
	// ("webauthn.create" for registrations, "webauthn.get" for logins).
	clientDataType string

	// crossOrigin is the client data crossOrigin member. If nil, the
	// member is omitted.
	crossOrigin *bool

	// clientDataExtra members are added to the client data JSON
	// (e.g. topOrigin), overriding the standard ones on collision.
	clientDataExtra map[string]any

	sign func(message []byte) ([]byte, error)
}

// rsaKey is generated once: 2048-bit RSA key generation is slow enough
// to dominate the test suite otherwise.
var rsaKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

func newAuthenticator(t testing.TB, alg int32) *authenticator {
	t.Helper()
	a := &authenticator{
		aaguid:       [16]byte{0x01, 0x02, 0x03, 0x04},
		credentialID: make([]byte, 32),
		alg:          alg,
		transports:   []string{"internal", "hybrid"},
		crossOrigin:  new(bool), // false, but present
	}
	rand.Read(a.credentialID)

	switch alg {
	case algES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		point, err := key.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		x, y := point[1:33], point[33:65]
		a.coseKey = cborAppendMapHeader(nil, 5)
		a.coseKey = cborAppendInt(a.coseKey, 1)
		a.coseKey = cborAppendInt(a.coseKey, coseKeyTypeEC2)
		a.coseKey = cborAppendInt(a.coseKey, 3)
		a.coseKey = cborAppendInt(a.coseKey, algES256)
		a.coseKey = cborAppendInt(a.coseKey, -1)
		a.coseKey = cborAppendInt(a.coseKey, coseCurveP256)
		a.coseKey = cborAppendInt(a.coseKey, -2)
		a.coseKey = cborAppendBytes(a.coseKey, x)
		a.coseKey = cborAppendInt(a.coseKey, -3)
		a.coseKey = cborAppendBytes(a.coseKey, y)
		a.sign = func(message []byte) ([]byte, error) {
			digest := sha256.Sum256(message)
			return ecdsa.SignASN1(rand.Reader, key, digest[:])
		}

	case algRS256:
		key := rsaKey()
		e := binary.BigEndian.AppendUint32(nil, uint32(key.E))
		for len(e) > 1 && e[0] == 0 {
			e = e[1:]
		}
		a.coseKey = cborAppendMapHeader(nil, 4)
		a.coseKey = cborAppendInt(a.coseKey, 1)
		a.coseKey = cborAppendInt(a.coseKey, coseKeyTypeRSA)
		a.coseKey = cborAppendInt(a.coseKey, 3)
		a.coseKey = cborAppendInt(a.coseKey, algRS256)
		a.coseKey = cborAppendInt(a.coseKey, -1)
		a.coseKey = cborAppendBytes(a.coseKey, key.N.Bytes())
		a.coseKey = cborAppendInt(a.coseKey, -2)
		a.coseKey = cborAppendBytes(a.coseKey, e)
		a.sign = func(message []byte) ([]byte, error) {
			digest := sha256.Sum256(message)
			return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		}

	case algMLDSA44, algMLDSA65, algMLDSA87:
		params := map[int32]*mldsa.Parameters{
			algMLDSA44: mldsa.MLDSA44(), algMLDSA65: mldsa.MLDSA65(), algMLDSA87: mldsa.MLDSA87(),
		}[alg]
		key, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatal(err)
		}
		a.coseKey = cborAppendMapHeader(nil, 3)
		a.coseKey = cborAppendInt(a.coseKey, 1)
		a.coseKey = cborAppendInt(a.coseKey, coseKeyTypeAKP)
		a.coseKey = cborAppendInt(a.coseKey, 3)
		a.coseKey = cborAppendInt(a.coseKey, alg)
		a.coseKey = cborAppendInt(a.coseKey, -1)
		a.coseKey = cborAppendBytes(a.coseKey, key.PublicKey().Bytes())
		a.sign = func(message []byte) ([]byte, error) {
			// Pure ML-DSA, empty context, no prehashing.
			return key.Sign(rand.Reader, message, nil)
		}

	default:
		t.Fatalf("unknown algorithm %d", alg)
	}
	return a
}

// authData assembles authenticator data for the given RP ID. If attested
// is true, the attested credential data (AAGUID, credential ID, COSE
// key) is included and the AT flag is set. The ED flag is set if
// extensions are present.
func (a *authenticator) authData(rpID string, attested bool, flags byte) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	if attested {
		flags |= flagAT
	}
	if len(a.extensions) > 0 {
		flags |= flagED
	}
	b := append([]byte{}, rpIDHash[:]...)
	b = append(b, flags)
	b = binary.BigEndian.AppendUint32(b, 0) // signature counter
	if attested {
		b = append(b, a.aaguid[:]...)
		b = binary.BigEndian.AppendUint16(b, uint16(len(a.credentialID)))
		b = append(b, a.credentialID...)
		b = append(b, a.coseKey...)
	}
	return append(b, a.extensions...)
}

// clientDataJSON serializes the client data. challenge is base64url, as
// found in the ceremony options.
func (a *authenticator) clientDataJSON(t testing.TB, ceremonyType, challenge, origin string) []byte {
	t.Helper()
	if a.clientDataType != "" {
		ceremonyType = a.clientDataType
	}
	m := map[string]any{
		"type":      ceremonyType,
		"challenge": challenge,
		"origin":    origin,
	}
	if a.crossOrigin != nil {
		m["crossOrigin"] = *a.crossOrigin
	}
	maps.Copy(m, a.clientDataExtra)
	return mustJSON(t, m)
}

// registrationResponse produces a RegistrationResponseJSON as a map, to
// be marshaled with mustJSON, so that tests can modify any field first.
// Fields this package deliberately ignores (id, attestationObject,
// publicKeyAlgorithm) are populated anyway, to catch them being
// accidentally parsed.
func (a *authenticator) registrationResponse(t testing.TB, rpID, origin, challenge string, flags byte) map[string]any {
	t.Helper()
	authData := a.authData(rpID, true, flags)
	attObj := cborAppendMapHeader(nil, 3)
	attObj = cborAppendString(attObj, "fmt")
	attObj = cborAppendString(attObj, "none")
	attObj = cborAppendString(attObj, "attStmt")
	attObj = cborAppendMapHeader(attObj, 0)
	attObj = cborAppendString(attObj, "authData")
	attObj = cborAppendBytes(attObj, authData)

	return map[string]any{
		"id":                      base64.RawURLEncoding.EncodeToString(a.credentialID),
		"rawId":                   base64.RawURLEncoding.EncodeToString(a.credentialID),
		"type":                    "public-key",
		"authenticatorAttachment": "platform",
		"response": map[string]any{
			"clientDataJSON":     base64.RawURLEncoding.EncodeToString(a.clientDataJSON(t, "webauthn.create", challenge, origin)),
			"authenticatorData":  base64.RawURLEncoding.EncodeToString(authData),
			"attestationObject":  base64.RawURLEncoding.EncodeToString(attObj),
			"transports":         a.transports,
			"publicKeyAlgorithm": a.alg,
		},
		"clientExtensionResults": map[string]any{
			"credProps": map[string]any{"rk": true},
		},
	}
}

// loginResponse produces an AuthenticationResponseJSON as a map, to be
// marshaled with mustJSON, asserting the credential over the given
// challenge (base64url, as found in the request options). If userID is
// empty, the userHandle field is omitted.
func (a *authenticator) loginResponse(t testing.TB, rpID, origin, challenge, userID string, flags byte) map[string]any {
	t.Helper()
	authData := a.authData(rpID, false, flags)
	clientData := a.clientDataJSON(t, "webauthn.get", challenge, origin)
	return a.signedLoginResponse(t, authData, clientData, userID)
}

// signedLoginResponse assembles an AuthenticationResponseJSON from
// explicit authenticator data and client data, signed with the
// credential key. It gives tests full control of the signed material.
func (a *authenticator) signedLoginResponse(t testing.TB, authData, clientData []byte, userID string) map[string]any {
	t.Helper()
	clientDataHash := sha256.Sum256(clientData)
	signature, err := a.sign(append(append([]byte{}, authData...), clientDataHash[:]...))
	if err != nil {
		t.Fatal(err)
	}
	response := map[string]any{
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
		"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
		"signature":         base64.RawURLEncoding.EncodeToString(signature),
	}
	if userID != "" {
		response["userHandle"] = base64.RawURLEncoding.EncodeToString([]byte(userID))
	}
	return map[string]any{
		"id":                      base64.RawURLEncoding.EncodeToString(a.credentialID),
		"rawId":                   base64.RawURLEncoding.EncodeToString(a.credentialID),
		"type":                    "public-key",
		"authenticatorAttachment": "platform",
		"response":                response,
		"clientExtensionResults":  map[string]any{},
	}
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// challengeOf extracts the challenge from ceremony options, so that
// tests can hand it back to the authenticator.
func challengeOf(t testing.TB, optionsJSON []byte) string {
	t.Helper()
	var o struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		t.Fatal(err)
	}
	return o.Challenge
}

// The cborAppend functions encode CTAP2 canonical CBOR, the encoding
// counterpart of internal/ctap2cbor.

func cborAppendArgument(b []byte, major byte, arg uint16) []byte {
	switch {
	case arg <= 23:
		return append(b, major<<5|byte(arg))
	case arg <= 0xff:
		return append(b, major<<5|24, byte(arg))
	default:
		return append(b, major<<5|25, byte(arg>>8), byte(arg))
	}
}

func cborAppendInt(b []byte, v int32) []byte {
	if v < 0 {
		return cborAppendArgument(b, 1, uint16(-(v + 1)))
	}
	return cborAppendArgument(b, 0, uint16(v))
}

func cborAppendBytes(b []byte, v []byte) []byte {
	b = cborAppendArgument(b, 2, uint16(len(v)))
	return append(b, v...)
}

func cborAppendString(b []byte, v string) []byte {
	b = cborAppendArgument(b, 3, uint16(len(v)))
	return append(b, v...)
}

func cborAppendMapHeader(b []byte, pairs uint16) []byte {
	return cborAppendArgument(b, 5, pairs)
}
