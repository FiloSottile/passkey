package passkey

import (
	"bytes"
	"encoding/base64"
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

// loadWebAuthnVectors reads the testdata/webauthn.json vectors.
func loadWebAuthnVectors(t testing.TB) webauthnVectorFile {
	t.Helper()
	data, err := os.ReadFile("testdata/webauthn.json")
	if err != nil {
		t.Fatal(err)
	}
	var f webauthnVectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestWebAuthnVectors replays the §16 ceremonies: registrations must
// produce records carrying the vector's values, and the assertions,
// signed by the same credentials, must verify against those records.
func TestWebAuthnVectors(t *testing.T) {
	f := loadWebAuthnVectors(t)
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

	record, err := rp.Register(mustJSON(t, map[string]any{
		"id":    b64(v.CredentialID),
		"rawId": b64(v.CredentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(v.Registration.ClientDataJSON),
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
		r := mustParseRecord(t, record)
		if backedUp := r.flags.backupState(); backedUp != v.Registration.BackedUp {
			t.Errorf("backup state = %v, want %v", backedUp, v.Registration.BackedUp)
		}
		if !bytes.Equal(r.credentialID, v.CredentialID) {
			t.Errorf("credentialID = %x, want %x", r.credentialID, v.CredentialID)
		}
	}

	// The vectors carry no user handle, which is not signed, so one is
	// supplied: whether the ceremony is user-scoped is decided by the
	// vector's fixed challenge, and an unscoped login requires a handle.
	const userID = "kaHmSAdCq9BGgqNhPRRTvw"
	resp, err := ParseResponse(mustJSON(t, map[string]any{
		"id":    b64(v.CredentialID),
		"rawId": b64(v.CredentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(v.Authentication.ClientDataJSON),
			"authenticatorData": b64(v.Authentication.AuthenticatorData),
			"signature":         b64(v.Authentication.Signature),
			"userHandle":        b64([]byte(userID)),
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
	wantUserID := userID
	if userScoped([32]byte(v.Authentication.Challenge)) {
		wantUserID = ""
	}
	if got := resp.UnauthenticatedUserID(); got != wantUserID {
		t.Errorf("UnauthenticatedUserID() = %q, want %q", got, wantUserID)
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
