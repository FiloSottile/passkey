package passkey

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// Test vectors from §16 of WebAuthn Level 3, replayed as full ceremonies.

// webauthnVectorFile is testdata/webauthn.json.
type webauthnVectorFile struct {
	Source  string           `json:"source"`
	RPID    string           `json:"rpId"`
	Origin  string           `json:"origin"`
	Vectors []webauthnVector `json:"vectors"`
}

// webauthnVector is a registration and an authentication ceremony
// performed with the same credential, and the values they carry.
type webauthnVector struct {
	Name         string   `json:"name"`
	Algorithm    int32    `json:"algorithm"`
	AAGUID       hexBytes `json:"aaguid"`
	CredentialID hexBytes `json:"credentialId"`
	Registration struct {
		Challenge         hexBytes `json:"challenge"`
		ClientDataJSON    hexBytes `json:"clientDataJSON"`
		AttestationObject hexBytes `json:"attestationObject"`
		CrossOrigin       bool     `json:"crossOrigin"`
		TopOrigin         string   `json:"topOrigin"`
		BackedUp          bool     `json:"backedUp"`
	} `json:"registration"`
	Authentication struct {
		Challenge         hexBytes `json:"challenge"`
		ClientDataJSON    hexBytes `json:"clientDataJSON"`
		AuthenticatorData hexBytes `json:"authenticatorData"`
		Signature         hexBytes `json:"signature"`
		CrossOrigin       bool     `json:"crossOrigin"`
		TopOrigin         string   `json:"topOrigin"`
		UserVerified      bool     `json:"userVerified"`
		BackedUp          bool     `json:"backedUp"`
	} `json:"authentication"`
}

// hexBytes is a byte string in the hex encoding the vectors use.
type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = b
	return nil
}

// Substrings of the errors the rejected vectors must fail with.
const (
	crossOriginError          = "cross-origin frame"
	unsupportedAlgorithmError = "unsupported credential public key algorithm"
	malformedChallengeError   = "malformed challenge"
)

// webauthnVectorOutcome returns substrings of the errors this package
// must reject the vector's ceremonies with, if any: no cross-origin
// ceremonies (marked by crossOrigin or by topOrigin), only ES256, RS256
// and ML-DSA-44 credentials, and only 32-byte assertion challenges. The
// cases are in check order, so a vector that trips two expects the first.
func webauthnVectorOutcome(v webauthnVector) (registerErr, parseErr string) {
	switch {
	case v.Registration.CrossOrigin || v.Registration.TopOrigin != "":
		registerErr = crossOriginError
	case v.Algorithm != algES256 && v.Algorithm != algRS256 && v.Algorithm != algMLDSA44:
		registerErr = unsupportedAlgorithmError
	}
	switch {
	case v.Authentication.CrossOrigin || v.Authentication.TopOrigin != "":
		parseErr = crossOriginError
	case len(v.Authentication.Challenge) != 32:
		parseErr = malformedChallengeError
	}
	return registerErr, parseErr
}

// TestWebAuthnVectors replays the §16 ceremonies: registrations must
// produce records carrying the vector's values, and the assertions,
// signed by the same credentials, must verify against those records.
func TestWebAuthnVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/webauthn.json")
	if err != nil {
		t.Fatal(err)
	}
	var f webauthnVectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	rp, err := NewRelyingParty(&Options{RPID: f.RPID, Origin: f.Origin})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			testWebAuthnVector(t, rp, v)
		})
	}
}

func testWebAuthnVector(t *testing.T, rp *RelyingParty, v webauthnVector) {
	b64 := base64.RawURLEncoding.EncodeToString
	wantRegisterErr, wantParseErr := webauthnVectorOutcome(v)

	// The vectors publish only the attestation object, so the
	// authenticator data this package requires is lifted out of it.
	record, err := rp.Register(mustJSON(t, map[string]any{
		"id":    b64(v.CredentialID),
		"rawId": b64(v.CredentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(v.Registration.ClientDataJSON),
			"authenticatorData": b64(attestationObjectAuthData(t, v.Registration.AttestationObject)),
			"attestationObject": b64(v.Registration.AttestationObject),
		},
		// No credProps output, which is accepted: not every client reports it.
		"clientExtensionResults": map[string]any{},
	}))
	switch {
	case wantRegisterErr != "":
		if err == nil {
			t.Fatalf("Register() succeeded, want an error containing %q", wantRegisterErr)
		}
		if !strings.Contains(err.Error(), wantRegisterErr) {
			t.Errorf("Register() = %v, want it to contain %q", err, wantRegisterErr)
		}
		if wantRegisterErr == unsupportedAlgorithmError && !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("Register() = %v, want errors.Is(err, ErrUnsupportedAlgorithm)", err)
		}
	case err != nil:
		t.Fatalf("Register() = %v, want success", err)
	default:
		aaguid, err := AAGUID(record)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(aaguid[:], v.AAGUID) {
			t.Errorf("AAGUID() = %x, want %x", aaguid, v.AAGUID)
		}
		if backedUp, err := BackedUp(record); err != nil || backedUp != v.Registration.BackedUp {
			t.Errorf("BackedUp() = %v, %v, want %v", backedUp, err, v.Registration.BackedUp)
		}
		// The credential ID has no exported accessor.
		r, err := parseRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(r.credentialID, v.CredentialID) {
			t.Errorf("credentialID = %x, want %x", r.credentialID, v.CredentialID)
		}
	}

	resp, err := ParseResponse(mustJSON(t, map[string]any{
		"id":    b64(v.CredentialID),
		"rawId": b64(v.CredentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(v.Authentication.ClientDataJSON),
			"authenticatorData": b64(v.Authentication.AuthenticatorData),
			"signature":         b64(v.Authentication.Signature),
			// The vectors carry no user handle, so the login below is
			// user-scoped: a scoped request accepts an assertion without one.
		},
		"clientExtensionResults": map[string]any{},
	}))
	if wantParseErr != "" {
		if err == nil {
			t.Fatalf("ParseResponse() succeeded, want an error containing %q", wantParseErr)
		}
		if !strings.Contains(err.Error(), wantParseErr) {
			t.Errorf("ParseResponse() = %v, want it to contain %q", err, wantParseErr)
		}
		return
	}
	if err != nil {
		t.Fatalf("ParseResponse() = %v, want success", err)
	}
	if resp.UserVerified() != v.Authentication.UserVerified {
		t.Errorf("UserVerified() = %v, want %v", resp.UserVerified(), v.Authentication.UserVerified)
	}
	if resp.BackedUp() != v.Authentication.BackedUp {
		t.Errorf("BackedUp() = %v, want %v", resp.BackedUp(), v.Authentication.BackedUp)
	}
	if record == "" {
		// The registration was rejected, so there is no record to log in against.
		return
	}

	// The login challenge is fixed by the vector, so the request is
	// assembled around it.
	request := (&loginRequest{
		challenge: [32]byte(v.Authentication.Challenge),
		created:   time.Now(),
		userID:    "kaHmSAdCq9BGgqNhPRRTvw",
	}).Bytes()
	if resp.RequestID() != RequestID(request) {
		t.Errorf("Response.RequestID() = %q, want %q", resp.RequestID(), RequestID(request))
	}
	matched, err := rp.Login(resp, request, []string{record})
	if err != nil {
		t.Fatalf("Login() = %v, want success", err)
	}
	if matched != 0 {
		t.Errorf("Login() matched record %d, want 0", matched)
	}
}

// attestationObjectAuthData returns the authData member of a CBOR
// attestation object, which fixtures that predate the authenticatorData
// response field serialize instead of it.
//
// Rather than parse CBOR, it takes the authData key, which comes last in
// the CTAP2 canonical order, and requires the byte string after it to run
// exactly to the end.
func attestationObjectAuthData(t testing.TB, attestationObject []byte) []byte {
	t.Helper()
	key := []byte("\x68authData") // the CBOR text string "authData"
	if n := bytes.Count(attestationObject, key); n != 1 {
		t.Fatalf("attestation object has %d authData members, want one", n)
	}
	b := attestationObject[bytes.Index(attestationObject, key)+len(key):]
	// A byte string header, with the length in the next one or two bytes:
	// authenticator data is never short enough for an immediate value.
	var length int
	switch {
	case len(b) > 1 && b[0] == 0x58:
		length, b = int(b[1]), b[2:]
	case len(b) > 2 && b[0] == 0x59:
		length, b = int(binary.BigEndian.Uint16(b[1:3])), b[3:]
	default:
		t.Fatal("attestation object authData is not a byte string")
	}
	if length != len(b) {
		t.Fatalf("attestation object authData is %d bytes, but %d bytes follow it", length, len(b))
	}
	return b
}
