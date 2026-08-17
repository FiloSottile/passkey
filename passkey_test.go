package passkey

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	testRPID   = "example.com"
	testOrigin = "https://example.com"
)

// lookalikeOrigins are origins that would be accepted by loose comparison.
var lookalikeOrigins = []string{
	"https://example.com.attacker.example",
	"https://accounts.example.com",
	"https://EXAMPLE.com",
	"http://example.com",
	"https://example.com:443",
	"https://example.com/",
}

func TestE2E(t *testing.T) {
	t.Run("ES256", func(t *testing.T) { testE2E(t, algES256) })
	t.Run("RS256", func(t *testing.T) { testE2E(t, algRS256) })
	t.Run("MLDSA44", func(t *testing.T) { testE2E(t, algMLDSA44) })
}

// testE2E runs full registration and login ceremonies for two passkeys
// of the same algorithm, through the exported API only.
func testE2E(t *testing.T, alg int32) {
	rp, err := NewRelyingParty(&Options{RPID: testRPID, Origin: testOrigin})
	if err != nil {
		t.Fatal(err)
	}
	user := User{ID: "wxJph3ZClFxTP2xF9r2W0A", Name: "user@example.com"}

	// Register a first passkey, from a backed-up credential.
	auth1 := newAuthenticator(t, alg)
	optionsJSON, err := rp.NewRegistration(user, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec1, err := rp.Register(mustJSON(t, auth1.registrationResponse(t, testRPID, testOrigin,
		challengeOf(t, optionsJSON), flagUP|flagUV|flagBE|flagBS)))
	if err != nil {
		t.Fatal(err)
	}

	// Register a second passkey, excluding the first.
	auth2 := newAuthenticator(t, alg)
	auth2.transports = nil
	optionsJSON, err = rp.NewRegistration(user, []string{rec1})
	if err != nil {
		t.Fatal(err)
	}
	var creation struct {
		ExcludeCredentials []credentialDescriptor `json:"excludeCredentials"`
	}
	if err := json.Unmarshal(optionsJSON, &creation); err != nil {
		t.Fatal(err)
	}
	wantID := base64.RawURLEncoding.EncodeToString(auth1.credentialID)
	if len(creation.ExcludeCredentials) != 1 || creation.ExcludeCredentials[0].ID != wantID {
		t.Errorf("excludeCredentials = %+v, want one entry with ID %q", creation.ExcludeCredentials, wantID)
	}
	rec2, err := rp.Register(mustJSON(t, auth2.registrationResponse(t, testRPID, testOrigin,
		challengeOf(t, optionsJSON), flagUP|flagUV)))
	if err != nil {
		t.Fatal(err)
	}

	records := []string{rec1, rec2}

	// Record accessors.
	if aaguid, err := AAGUID(rec1); err != nil || aaguid != auth1.aaguid {
		t.Errorf("AAGUID(rec1) = %x, %v, want %x", aaguid, err, auth1.aaguid)
	}
	if transports, err := Transports(rec1); err != nil || !slices.Equal(transports, []string{"hybrid", "internal"}) {
		t.Errorf("Transports(rec1) = %q, %v, want [hybrid internal]", transports, err)
	}
	if transports, err := Transports(rec2); err != nil || transports != nil {
		t.Errorf("Transports(rec2) = %q, %v, want none", transports, err)
	}
	r1 := mustParseRecord(t, rec1)
	if !r1.flags.backupState() {
		t.Error("rec1 backup state = false, want true")
	}
	r2 := mustParseRecord(t, rec2)
	if r2.flags.backupState() {
		t.Error("rec2 backup state = true, want false")
	}

	// Unscoped login, with the second passkey. allowCredentials serializes
	// as an empty array, not null.
	request, optionsJSON, err := rp.NewLogin()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(optionsJSON), `"allowCredentials":[]`) {
		t.Errorf("options = %s, want an empty allowCredentials list", optionsJSON)
	}
	if created := RequestCreation(request); created.IsZero() || time.Since(created) > time.Minute {
		t.Errorf("RequestCreation() = %v, want approximately now", created)
	}
	if RequestID(request) == "" {
		t.Error("RequestID() is empty")
	}
	resp, err := ParseResponse(mustJSON(t, auth2.loginResponse(t, testRPID, testOrigin,
		challengeOf(t, optionsJSON), user.ID, flagUP|flagUV)))
	if err != nil {
		t.Fatal(err)
	}
	// The application looks up the stored request by response ID, and the
	// user's records by the asserted user ID.
	if resp.RequestID() != RequestID(request) {
		t.Errorf("Response.RequestID() = %q, want %q", resp.RequestID(), RequestID(request))
	}
	if got := resp.UnauthenticatedUserID(); got != user.ID {
		t.Errorf("UnauthenticatedUserID() = %q, want %q", got, user.ID)
	}
	result, err := rp.Login(resp, request, records)
	if err != nil {
		t.Fatal(err)
	}
	if want := (&LoginResult{Matched: 1, UserVerified: true}); *result != *want {
		t.Errorf("Login() = %+v, want %+v", result, want)
	}

	// User-scoped login, with the first passkey. The response asserts
	// the user handle, as clients generally do even with
	// allowCredentials, but the application already identified the
	// user, so it is not exposed.
	request, optionsJSON, err = rp.NewLoginWithCredentials(records)
	if err != nil {
		t.Fatal(err)
	}
	var reqOpts struct {
		AllowCredentials []credentialDescriptor `json:"allowCredentials"`
	}
	if err := json.Unmarshal(optionsJSON, &reqOpts); err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{
		base64.RawURLEncoding.EncodeToString(auth1.credentialID),
		base64.RawURLEncoding.EncodeToString(auth2.credentialID),
	}
	var gotIDs []string
	for _, c := range reqOpts.AllowCredentials {
		gotIDs = append(gotIDs, c.ID)
	}
	if !slices.Equal(gotIDs, wantIDs) {
		t.Errorf("allowCredentials IDs = %q, want %q", gotIDs, wantIDs)
	}
	resp, err = ParseResponse(mustJSON(t, auth1.loginResponse(t, testRPID, testOrigin,
		challengeOf(t, optionsJSON), user.ID, flagUP|flagUV|flagBE|flagBS)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.RequestID() != RequestID(request) {
		t.Errorf("Response.RequestID() = %q, want %q", resp.RequestID(), RequestID(request))
	}
	if got := resp.UnauthenticatedUserID(); got != "" {
		t.Errorf("UnauthenticatedUserID() = %q, want empty", got)
	}
	result, err = rp.Login(resp, request, records)
	if err != nil {
		t.Fatal(err)
	}
	if want := (&LoginResult{Matched: 0, UserVerified: true, BackedUp: true}); *result != *want {
		t.Errorf("Login() = %+v, want %+v", result, want)
	}
}

func TestNewRelyingPartyNilOptions(t *testing.T) {
	if _, err := NewRelyingParty(nil); err == nil {
		t.Error("NewRelyingParty(nil) succeeded, want error")
	}
}

// TestNewRelyingPartyOrigin checks the Origin validation against real
// origin shapes. The check is a character-set footgun check, not a
// parser: values that could never match a serialized origin are
// accepted and simply never match.
func TestNewRelyingPartyOrigin(t *testing.T) {
	valid := []string{
		"https://example.com",
		"https://accounts.example.com",
		"https://example.com:8443",
		"http://localhost:8080",
		"android:apk-key-hash:cKDrEhH_wGil0eBJcvSCJxgW6ZP2PGGl8sM1SluBSuw",
	}
	invalid := []string{
		"",
		"example.com",
		"https://example.com/",
		"https://example.com/login",
		"HTTPS://example.com",
		"https://Example.com",
		"https://*.example.com",
		"https://",
		"://example.com",
		"https://exa mple.com",
	}
	for _, origin := range valid {
		if _, err := NewRelyingParty(&Options{RPID: "example.com", Origin: origin}); err != nil {
			t.Errorf("NewRelyingParty(Origin: %q) = %v, want success", origin, err)
		}
	}
	for _, origin := range invalid {
		if _, err := NewRelyingParty(&Options{RPID: "example.com", Origin: origin}); err == nil {
			t.Errorf("NewRelyingParty(Origin: %q) succeeded, want error", origin)
		}
	}
}

func TestNewRelyingPartyRPID(t *testing.T) {
	valid := []string{
		"example.com",
		"localhost",
		"accounts.example.co.uk",
		"xn--dmin-moa0i.example",
		"a.b-c.d",
		strings.Repeat("a", 255),
	}
	invalid := []string{
		"",
		".",
		"example.com.",
		".example.com",
		"Example.com",
		"exa_mple.com",
		"*.example.com",
		"192.168.1.1",
		strings.Repeat("a", 256),
	}
	for _, rpID := range valid {
		if _, err := NewRelyingParty(&Options{RPID: rpID, Origin: "https://example.com"}); err != nil {
			t.Errorf("NewRelyingParty(RPID: %q) = %v, want success", rpID, err)
		}
	}
	for _, rpID := range invalid {
		if _, err := NewRelyingParty(&Options{RPID: rpID, Origin: "https://example.com"}); err == nil {
			t.Errorf("NewRelyingParty(RPID: %q) succeeded, want error", rpID)
		}
	}
}

// TestNewRelyingPartyTimeout checks the Timeout option handling: a
// negative value is rejected, zero defaults to five minutes, and values
// above the WebIDL unsigned long range are rejected.
func TestNewRelyingPartyTimeout(t *testing.T) {
	if _, err := NewRelyingParty(&Options{RPID: "example.com", Origin: "https://example.com",
		Timeout: -1}); err == nil {
		t.Error("NewRelyingParty(Timeout: -1) succeeded, want error")
	}
	if _, err := NewRelyingParty(&Options{RPID: "example.com", Origin: "https://example.com",
		Timeout: (math.MaxUint32 + 1) * time.Millisecond}); err == nil {
		t.Error("NewRelyingParty() with an oversized Timeout succeeded, want error")
	}

	rp, err := NewRelyingParty(&Options{RPID: "example.com", Origin: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if rp.timeout != 5*time.Minute {
		t.Errorf("timeout = %v, want the 5 minute default", rp.timeout)
	}

	rp, err = NewRelyingParty(&Options{RPID: "example.com", Origin: "https://example.com",
		Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if rp.timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", rp.timeout)
	}

	if _, err := NewRelyingParty(&Options{RPID: "example.com", Origin: "https://example.com",
		Timeout: math.MaxUint32 * time.Millisecond}); err != nil {
		t.Errorf("NewRelyingParty() with the maximum Timeout = %v, want success", err)
	}
}
