package passkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/mldsa"
)

// fuzzAlgorithms are the credential algorithms the seed ceremonies cover.
var fuzzAlgorithms = []int32{algES256, algRS256, algMLDSA44}

// fuzzCeremony is a registration and a login ceremony, valid when built,
// seeding the targets with material that reaches past the first check.
type fuzzCeremony struct {
	rp   *RelyingParty
	auth *authenticator
	user User

	creationChallenge string
	registrationJSON  []byte
	record            string

	request      []byte
	authData     []byte
	clientData   []byte
	responseJSON []byte
}

func newFuzzCeremony(f *testing.F, alg int32, opts Options) *fuzzCeremony {
	f.Helper()
	c := &fuzzCeremony{
		rp:   newTestRP(f, opts),
		auth: newAuthenticator(f, alg),
		user: User{ID: "wxJph3ZClFxTP2xF9r2W0A", Name: "user@example.com"},
	}

	creationJSON, err := c.rp.NewRegistration(c.user, nil)
	if err != nil {
		f.Fatal(err)
	}
	c.creationChallenge = challengeOf(f, creationJSON)
	c.registrationJSON = mustJSON(f, c.auth.registrationResponse(f, testRPID, testOrigin,
		c.creationChallenge, flagUP|flagUV))
	c.record, err = c.rp.Register(c.registrationJSON)
	if err != nil {
		f.Fatal(err)
	}

	request, requestJSON, err := c.rp.NewLogin()
	if err != nil {
		f.Fatal(err)
	}
	c.request = request
	c.authData = c.auth.authData(testRPID, false, flagUP|flagUV)
	c.clientData = c.auth.clientDataJSON(f, "webauthn.get", challengeOf(f, requestJSON), testOrigin)
	c.responseJSON = mustJSON(f, c.auth.signedLoginResponse(f, c.authData, c.clientData, c.user.ID))
	return c
}

// registrationAuthData returns the payload of the ceremony's record.
func (c *fuzzCeremony) registrationAuthData() []byte {
	return c.auth.authData(testRPID, true, flagUP|flagUV)
}

// validTransports reports whether every element of ts is a valid
// transport, the condition for surviving a record round trip.
func validTransports(ts []string) bool {
	for _, transport := range ts {
		if !validTransport(transport) {
			return false
		}
	}
	return true
}

// FuzzParseRecord checks that the accessors and credentialDescriptors
// accept exactly the records parseRecord does.
func FuzzParseRecord(f *testing.F) {
	for _, v := range loadRecordVectors(f) {
		f.Add(v.Record)
	}
	for _, alg := range fuzzAlgorithms {
		f.Add(newFuzzCeremony(f, alg, Options{}).record)
	}
	f.Add("")
	f.Add("$webauthn$v=1$")

	f.Fuzz(func(t *testing.T, s string) {
		r, err := parseRecord(s)

		_, aaguidErr := AAGUID(s)
		_, backedUpErr := BackedUp(s)
		_, transportsErr := Transports(s)
		descriptors := credentialDescriptors([]string{s})
		if err != nil {
			if aaguidErr == nil || backedUpErr == nil || transportsErr == nil {
				t.Errorf("parseRecord() = %v, but AAGUID() = %v, BackedUp() = %v, Transports() = %v",
					err, aaguidErr, backedUpErr, transportsErr)
			}
			if len(descriptors) != 0 {
				t.Errorf("parseRecord() = %v, but credentialDescriptors() returned %d descriptors",
					err, len(descriptors))
			}
			checkWrapped(t, aaguidErr)
			return
		}
		checkRecord(t, s, r)
	})
}

// FuzzRecordRoundTrip builds records from arbitrary authenticator data,
// reaching the authenticator data and COSE key parsers that mutations of
// a base64 field rarely would.
func FuzzRecordRoundTrip(f *testing.F) {
	for _, alg := range fuzzAlgorithms {
		f.Add(newFuzzCeremony(f, alg, Options{}).registrationAuthData(), "internal+hybrid")
	}
	for _, v := range loadWebAuthnVectors(f).Vectors {
		f.Add(attestationObjectAuthData(f, v.Registration.AttestationObject), "")
	}
	f.Add([]byte(nil), "usb")

	f.Fuzz(func(t *testing.T, authData []byte, transports string) {
		var ts []string
		if transports != "" {
			ts = strings.Split(transports, "+")
		}
		s := encodeRecord(authData, ts)
		r, err := parseRecord(s)
		if err != nil {
			return
		}
		// encodeRecord doesn't sanitize: a transport carrying a "," is
		// encoded as a second parameter. Register only passes valid ones.
		if validTransports(ts) && !slices.Equal(r.transports, ts) {
			t.Errorf("parseRecord() transports = %q, want the encoded %q", r.transports, ts)
		}
		checkRecord(t, s, r)
	})
}

// FuzzRegister checks that every record Register produces parses: a
// record only the encoder accepts locks the user out at the next login.
func FuzzRegister(f *testing.F) {
	rp := newTestRP(f, Options{})
	for _, alg := range fuzzAlgorithms {
		f.Add(newFuzzCeremony(f, alg, Options{}).registrationJSON)
	}
	// Extension outputs, so the ED flag and trailing bytes are reachable.
	extended := newFuzzCeremony(f, algES256, Options{})
	extended.auth.extensions = []byte{0xa0} // an empty CBOR map
	f.Add(mustJSON(f, extended.auth.registrationResponse(f, testRPID, testOrigin,
		extended.creationChallenge, flagUP|flagUV)))
	f.Add([]byte("{}"))

	f.Fuzz(func(t *testing.T, responseJSON []byte) {
		s, err := rp.Register(responseJSON)
		if err != nil {
			if s != "" {
				t.Errorf("Register() = %q with error %v, want an empty record", s, err)
			}
			checkWrapped(t, err)
			return
		}
		r, err := parseRecord(s)
		if err != nil {
			t.Fatalf("Register() produced a record that does not parse: %v (%q)", err, s)
		}
		if r.rpIDHash != sha256.Sum256([]byte(testRPID)) {
			t.Error("Register() produced a record for a different RP ID")
		}
		checkRecord(t, s, r)
	})
}

// checkRecord asserts what parseRecord promises of every record it
// accepts: the encoding is the only one of its value, the accessors
// agree with it, and the fields are within bounds.
func checkRecord(t *testing.T, s string, r *record) {
	t.Helper()

	// The final field is canonical base64 of the authenticator data, and
	// re-encoding the record from its parts is a fixpoint.
	authData, err := base64.RawStdEncoding.Strict().DecodeString(s[strings.LastIndex(s, "$")+1:])
	if err != nil {
		t.Fatalf("record was accepted but its final field is not canonical base64: %v", err)
	}
	canonical := encodeRecord(authData, r.transports)
	again, err := parseRecord(canonical)
	if err != nil {
		t.Fatalf("re-encoded record does not parse: %v (%q)", err, canonical)
	}
	if got := encodeRecord(authData, again.transports); got != canonical {
		t.Errorf("re-encoding is not a fixpoint: %q became %q", canonical, got)
	}
	if !bytes.Equal(again.credentialID, r.credentialID) || again.aaguid != r.aaguid ||
		again.flags != r.flags || again.rpIDHash != r.rpIDHash ||
		!slices.Equal(again.transports, r.transports) {
		t.Errorf("re-encoded record %q parses to different values", canonical)
	}

	if len(r.credentialID) < 16 || len(r.credentialID) > 1023 {
		t.Errorf("credential ID is %d bytes, want between 16 and 1023", len(r.credentialID))
	}
	if !r.flags.attestedData() {
		t.Error("record has no attested credential data")
	}
	if r.flags.backupState() && !r.flags.backupEligible() {
		t.Error("record is backed up but not backup eligible")
	}
	if len(r.transports) > 32 {
		t.Errorf("record has %d transports, want at most 32", len(r.transports))
	}
	for i, transport := range r.transports {
		if !validTransport(transport) {
			t.Errorf("record has invalid transport %q", transport)
		}
		if i > 0 && r.transports[i-1] >= transport {
			t.Errorf("record transports are not sorted and deduplicated: %q", r.transports)
		}
	}
	switch r.key.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, *mldsa.PublicKey:
		// Whatever the parser returns can be verified against.
		if verifySignature(r.key, nil, nil) {
			t.Error("verifySignature() accepted an empty signature")
		}
	default:
		t.Errorf("record key has type %T, want a supported public key", r.key)
	}

	if aaguid, err := AAGUID(s); err != nil || aaguid != r.aaguid {
		t.Errorf("AAGUID() = %x, %v, want %x", aaguid, err, r.aaguid)
	}
	if backedUp, err := BackedUp(s); err != nil || backedUp != r.flags.backupState() {
		t.Errorf("BackedUp() = %v, %v, want %v", backedUp, err, r.flags.backupState())
	}
	if transports, err := Transports(s); err != nil || !slices.Equal(transports, r.transports) {
		t.Errorf("Transports() = %q, %v, want %q", transports, err, r.transports)
	}
	descriptors := credentialDescriptors([]string{s})
	if len(descriptors) != 1 {
		t.Fatalf("credentialDescriptors() = %v, want one descriptor", descriptors)
	}
	if descriptors[0].Type != "public-key" {
		t.Errorf("credential descriptor type = %q, want %q", descriptors[0].Type, "public-key")
	}
	if want := base64.RawURLEncoding.EncodeToString(r.credentialID); descriptors[0].ID != want {
		t.Errorf("credential descriptor ID = %q, want %q", descriptors[0].ID, want)
	}
	if !slices.Equal(descriptors[0].Transports, r.transports) {
		t.Errorf("credential descriptor transports = %q, want %q", descriptors[0].Transports, r.transports)
	}
}

// FuzzParseResponse checks that a parsed response reports what its
// authenticator data says, and says what ParseResponse requires.
func FuzzParseResponse(f *testing.F) {
	for _, alg := range fuzzAlgorithms {
		f.Add(newFuzzCeremony(f, alg, Options{}).responseJSON)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	for _, v := range loadWebAuthnVectors(f).Vectors {
		f.Add(mustJSON(f, map[string]any{
			"id":    b64(v.CredentialID),
			"rawId": b64(v.CredentialID),
			"type":  "public-key",
			"response": map[string]any{
				"clientDataJSON":    b64(v.Authentication.ClientDataJSON),
				"authenticatorData": b64(v.Authentication.AuthenticatorData),
				"signature":         b64(v.Authentication.Signature),
			},
		}))
	}
	f.Add([]byte("{}"))

	f.Fuzz(func(t *testing.T, responseJSON []byte) {
		r, err := ParseResponse(responseJSON)
		if err != nil {
			if r != nil {
				t.Errorf("ParseResponse() returned a response with error %v", err)
			}
			return
		}
		if len(r.credentialID) == 0 {
			t.Error("response has no credential ID")
		}
		if len(r.authData) < 37 {
			t.Fatalf("authenticator data is %d bytes, want at least 37", len(r.authData))
		}
		if !bytes.Equal(r.rpIDHash[:], r.authData[:32]) {
			t.Error("response RP ID hash is not the one in the authenticator data")
		}
		fl := flags(r.authData[32])
		if !fl.userPresent() {
			t.Error("response has no user presence flag")
		}
		if fl.attestedData() {
			t.Error("response has attested credential data")
		}
		if fl.extensionData() != (len(r.authData) > 37) {
			t.Errorf("extension data flag is %v with %d bytes of authenticator data",
				fl.extensionData(), len(r.authData))
		}
		if fl.backupState() && !fl.backupEligible() {
			t.Error("response is backed up but not backup eligible")
		}
		if r.UserVerified() != fl.userVerified() {
			t.Errorf("UserVerified() = %v, want %v", r.UserVerified(), fl.userVerified())
		}
		if r.BackedUp() != fl.backupState() {
			t.Errorf("BackedUp() = %v, want %v", r.BackedUp(), fl.backupState())
		}
		if n := len(r.UnauthenticatedUserID()); n > 64 {
			t.Errorf("user ID is %d bytes, want at most 64", n)
		}
		// The response identifies the request its challenge came from.
		request := (&loginRequest{challenge: r.challenge, created: time.Now()}).Bytes()
		if r.RequestID() != RequestID(request) || r.RequestID() == "" {
			t.Errorf("RequestID() = %q, want the request's %q", r.RequestID(), RequestID(request))
		}
	})
}

// FuzzParseLoginRequest checks that an accepted request re-serializes to
// itself, and that RequestID and RequestCreation agree with the parser
// on which requests are valid.
func FuzzParseLoginRequest(f *testing.F) {
	f.Add(newLoginRequest("").Bytes())
	f.Add(newLoginRequest("wxJph3ZClFxTP2xF9r2W0A").Bytes())
	f.Add(newLoginRequest(strings.Repeat("u", 64)).Bytes())
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseLoginRequest(b)
		id, created := RequestID(b), RequestCreation(b)
		if (id != "") != (err == nil) {
			t.Errorf("RequestID() = %q, but parseLoginRequest() = %v", id, err)
		}
		if created.IsZero() == (err == nil) {
			t.Errorf("RequestCreation() = %v, but parseLoginRequest() = %v", created, err)
		}
		if err != nil {
			return
		}
		if got := r.Bytes(); !bytes.Equal(got, b) {
			t.Errorf("re-serialized request = %x, want %x", got, b)
		}
		if len(r.userID) > 64 {
			t.Errorf("user ID is %d bytes, want at most 64", len(r.userID))
		}
		if !created.Equal(r.created) {
			t.Errorf("RequestCreation() = %v, want %v", created, r.created)
		}
		// The ID is a function of the challenge alone, so rewriting the
		// creation time keeps it.
		if got := RequestID(withRequestCreated(b, time.Unix(1, 0))); got != id {
			t.Errorf("RequestID() of a request with a rewritten time = %q, want %q", got, id)
		}
	})
}

// FuzzCOSEKey checks that a COSE key is exactly as long as parseCOSEKey
// says it is, which decides where the extension data begins, and that it
// is the only encoding of the key it holds.
func FuzzCOSEKey(f *testing.F) {
	for _, alg := range []int32{algES256, algRS256, algMLDSA44, algMLDSA65, algMLDSA87} {
		f.Add(newAuthenticator(f, alg).coseKey)
	}
	for _, v := range loadWebAuthnVectors(f).Vectors {
		f.Add(attestedCredentialKey(f, attestationObjectAuthData(f, v.Registration.AttestationObject)))
	}
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, b []byte) {
		key, rest, err := parseCOSEKey(b)
		if err != nil {
			return
		}
		consumed := b[:len(b)-len(rest)]
		if !bytes.Equal(b[len(consumed):], rest) {
			t.Fatalf("parseCOSEKey() returned %d trailing bytes that are not the input's", len(rest))
		}
		key2, rest2, err := parseCOSEKey(consumed)
		if err != nil || len(rest2) != 0 {
			t.Fatalf("the consumed prefix does not parse on its own: %v, %d trailing bytes", err, len(rest2))
		}
		encoded := encodeCOSEKey(t, key)
		if !bytes.Equal(encoded, consumed) {
			t.Errorf("re-encoded COSE key = %x, want %x", encoded, consumed)
		}
		if !bytes.Equal(encodeCOSEKey(t, key2), encoded) {
			t.Error("the consumed prefix parses to a different key")
		}
	})
}

// attestedCredentialKey returns everything after the credential ID of
// registration authenticator data: the COSE key and any extension data.
func attestedCredentialKey(t testing.TB, authData []byte) []byte {
	t.Helper()
	if len(authData) < 55 {
		t.Fatalf("authenticator data is %d bytes, too short for attested credential data", len(authData))
	}
	length := int(binary.BigEndian.Uint16(authData[53:55]))
	if len(authData) < 55+length {
		t.Fatalf("authenticator data is %d bytes, too short for a %d-byte credential ID",
			len(authData), length)
	}
	return authData[55+length:]
}

// FuzzLogin mutates a ceremony the package accepts. Login can only
// succeed on the material the credential signed, so anything else the
// mutator reaches is a field the package ignores.
func FuzzLogin(f *testing.F) {
	// The seed ceremony must outlast a fuzzing run, or every execution
	// would stop at the expiry check.
	opts := Options{Timeout: 30 * 24 * time.Hour}
	c := newFuzzCeremony(f, algES256, opts)
	uvRP := newTestRP(f, Options{RequireUserVerification: true, Timeout: opts.Timeout})

	// A record with the ceremony's credential ID but another key, which
	// the record scan has to look past.
	impostor := newAuthenticator(f, algES256)
	impostor.credentialID = c.auth.credentialID
	impostorRecord, err := c.rp.Register(mustJSON(f, impostor.registrationResponse(f,
		testRPID, testOrigin, c.creationChallenge, flagUP|flagUV)))
	if err != nil {
		f.Fatal(err)
	}
	passkeys := []string{"$webauthn$v=1$", impostorRecord, c.record}

	f.Add(c.request, c.responseJSON)
	f.Add(withRequestCreated(c.request, time.Unix(1, 0)), c.responseJSON)
	f.Add(c.request, mustJSON(f, c.auth.signedLoginResponse(f, c.authData, c.clientData, "")))
	f.Add([]byte(nil), c.responseJSON)

	f.Fuzz(func(t *testing.T, request, responseJSON []byte) {
		response, err := ParseResponse(responseJSON)
		if err != nil {
			return
		}
		matched, err := c.rp.Login(response, request, passkeys)
		if err != nil {
			if matched != 0 {
				t.Errorf("Login() = %d with error %v, want 0", matched, err)
			}
			checkWrapped(t, err)
			return
		}

		// The signed regions are the ceremony's, because the mutator
		// cannot produce a signature over anything else.
		if !bytes.Equal(response.authData, c.authData) {
			t.Error("Login() accepted mutated authenticator data")
		}
		if response.clientDataHash != sha256.Sum256(c.clientData) {
			t.Error("Login() accepted mutated client data")
		}
		if matched < 0 || matched >= len(passkeys) {
			t.Fatalf("Login() = %d, want an index into %d records", matched, len(passkeys))
		}
		if passkeys[matched] != c.record {
			t.Errorf("Login() matched record %d, want the one holding the signing key", matched)
		}
		if response.RequestID() != RequestID(request) {
			t.Errorf("Login() accepted a response for a different request: %q, want %q",
				response.RequestID(), RequestID(request))
		}
		if created := RequestCreation(request); time.Since(created) > opts.Timeout {
			t.Errorf("Login() accepted a request created at %v", created)
		}

		// User verification is gated on the response's flag alone.
		_, uvErr := uvRP.Login(response, request, passkeys)
		if uvErr == nil && !response.UserVerified() {
			t.Error("Login() accepted an unverified response with RequireUserVerification")
		}
		if errors.Is(uvErr, ErrUserVerificationRequired) && response.UserVerified() {
			t.Errorf("Login() = %v for a user-verified response", uvErr)
		}
	})
}
