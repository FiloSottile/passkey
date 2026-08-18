package passkey

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// testChallenge and testScopedChallenge are base64url challenges for
// ceremonies that don't need a request, such as ParseResponse tests: the
// first of a NewLogin ceremony, the second of one begun with
// LoginOptions.AllowCredentials.
var (
	testChallenge       = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	testScopedChallenge = base64.RawURLEncoding.EncodeToString(append([]byte{challengeUserScoped}, bytes.Repeat([]byte{0x42}, 31)...))
)

func newTestRP(t testing.TB, opts Options) *RelyingParty {
	t.Helper()
	if opts.RPID == "" {
		opts.RPID = testRPID
	}
	if opts.Origin == "" {
		opts.Origin = testOrigin
	}
	rp, err := NewRelyingParty(&opts)
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

// loginEnv is a registered ES256 passkey and an in-flight unscoped
// login ceremony, the starting point for most Login tests.
type loginEnv struct {
	rp      *RelyingParty
	auth    *authenticator
	user    User
	record  string
	records []string
	request []byte
	// challenge is the base64url challenge of request.
	challenge string
}

func newLoginEnv(t *testing.T) *loginEnv {
	t.Helper()
	rp := newTestRP(t, Options{})
	user := User{ID: "wxJph3ZClFxTP2xF9r2W0A", Name: "user@example.com"}
	auth := newAuthenticator(t, algES256)
	creationJSON, err := rp.NewRegistration(user, nil)
	if err != nil {
		t.Fatal(err)
	}
	record, err := rp.Register(mustJSON(t, auth.registrationResponse(t, testRPID, testOrigin,
		challengeOf(t, creationJSON), flagUP|flagUV)))
	if err != nil {
		t.Fatal(err)
	}
	request, requestJSON, err := rp.NewLogin()
	if err != nil {
		t.Fatal(err)
	}
	return &loginEnv{
		rp:        rp,
		auth:      auth,
		user:      user,
		record:    record,
		records:   []string{record},
		request:   request,
		challenge: challengeOf(t, requestJSON),
	}
}

// response returns a valid response map for the environment's ceremony.
func (env *loginEnv) response(t *testing.T, flags byte) map[string]any {
	t.Helper()
	return env.auth.loginResponse(t, testRPID, testOrigin, env.challenge, env.user.ID, flags)
}

// withRequestCreated returns a copy of a login request with the
// creation timestamp rewritten. The wire format is version, 32-byte
// challenge, then big-endian Unix seconds at [33:41].
func withRequestCreated(request []byte, created time.Time) []byte {
	b := slices.Clone(request)
	binary.BigEndian.PutUint64(b[33:41], uint64(created.Unix()))
	return b
}

// withRawID replaces the response's rawId, leaving the id field and the
// signed material untouched.
func withRawID(m map[string]any, id []byte) map[string]any {
	m["rawId"] = base64.RawURLEncoding.EncodeToString(id)
	return m
}

// impostorResponse returns a response asserting env's credential ID but
// signed by a freshly generated key.
func impostorResponse(t *testing.T, env *loginEnv) []byte {
	t.Helper()
	impostor := newAuthenticator(t, algES256)
	impostor.credentialID = env.auth.credentialID
	return mustJSON(t, impostor.loginResponse(t, testRPID, testOrigin, env.challenge, env.user.ID, flagUP|flagUV))
}

var sentinelErrors = []error{ErrRequestExpired, ErrUnknownCredential, ErrUserVerificationUnavailable, ErrUnsupportedAlgorithm}

// checkWrapped asserts that err is not a bare sentinel: they are
// documented as always wrapped.
func checkWrapped(t *testing.T, err error) {
	t.Helper()
	for _, sentinel := range sentinelErrors {
		if err == sentinel {
			t.Errorf("error is the bare %v sentinel, want it wrapped", sentinel)
		}
	}
}

// checkError asserts that err matches the wantIs sentinel (if any) and
// no other sentinel, that it is never a bare sentinel, and that it
// contains wantHas.
func checkError(t *testing.T, err error, wantIs error, wantHas string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if wantIs != nil && !errors.Is(err, wantIs) {
		t.Errorf("error = %v, want errors.Is(err, %v)", err, wantIs)
	}
	checkWrapped(t, err)
	for _, sentinel := range sentinelErrors {
		if sentinel != wantIs && errors.Is(err, sentinel) {
			t.Errorf("error = %v, unexpectedly matches sentinel %v", err, sentinel)
		}
	}
	if !strings.Contains(err.Error(), wantHas) {
		t.Errorf("error = %v, want it to contain %q", err, wantHas)
	}
}

// TestLogin exercises each Login check: every case is fully valid —
// including the signature, which is recomputed over any modified
// material — except for the one check under test. Masking cases then
// confirm that sentinel errors are unreachable when an earlier check
// also fails.
func TestLogin(t *testing.T) {
	otherChallenge := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xCC}, 32))
	unknownID := bytes.Repeat([]byte{0xEE}, 32)
	optionalUV := func(t *testing.T) *RelyingParty {
		return newTestRP(t, Options{OptionalUserVerification: true})
	}
	expired := func(env *loginEnv) []byte {
		return withRequestCreated(env.request, time.Now().Add(-6*time.Minute))
	}

	tests := []struct {
		name string
		// setup returns the RelyingParty, response JSON, and request
		// for the Login call.
		setup  func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte)
		ok     bool
		errIs  error
		errHas string
	}{
		{
			name: "valid",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				return env.rp, mustJSON(t, env.response(t, flagUP|flagUV)), env.request
			},
			ok: true,
		},
		{
			name: "malformed request",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				return env.rp, mustJSON(t, env.response(t, flagUP|flagUV)), []byte("bogus")
			},
			errHas: "invalid stored request",
		},
		{
			name: "unknown request version",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				request := slices.Clone(env.request)
				request[0] = 2
				return env.rp, mustJSON(t, env.response(t, flagUP|flagUV)), request
			},
			errHas: "unknown version",
		},
		{
			name: "challenge mismatch",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				m := env.auth.loginResponse(t, testRPID, testOrigin, otherChallenge, env.user.ID, flagUP|flagUV)
				return env.rp, mustJSON(t, m), env.request
			},
			errHas: "challenge does not match",
		},
		{
			name: "wrong origin",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				m := env.auth.loginResponse(t, testRPID, "https://attacker.example", env.challenge, env.user.ID, flagUP|flagUV)
				return env.rp, mustJSON(t, m), env.request
			},
			errHas: "is not the expected value",
		},
		{
			name: "wrong RP ID",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				m := env.auth.loginResponse(t, "attacker.example", testOrigin, env.challenge, env.user.ID, flagUP|flagUV)
				return env.rp, mustJSON(t, m), env.request
			},
			errHas: "assertion for a different RP ID",
		},
		{
			// The user handle plays no part in a user-scoped ceremony:
			// the records passed to Login identify the user.
			name: "scoped login with another user's handle",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				request, requestJSON, err := env.rp.NewLoginWithOptions(&LoginOptions{AllowCredentials: env.records})
				if err != nil {
					t.Fatal(err)
				}
				m := env.auth.loginResponse(t, testRPID, testOrigin, challengeOf(t, requestJSON), "someone-else", flagUP|flagUV)
				return env.rp, mustJSON(t, m), request
			},
			ok: true,
		},
		{
			name: "scoped login without user handle",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				request, requestJSON, err := env.rp.NewLoginWithOptions(&LoginOptions{AllowCredentials: env.records})
				if err != nil {
					t.Fatal(err)
				}
				m := env.auth.loginResponse(t, testRPID, testOrigin, challengeOf(t, requestJSON), "", flagUP|flagUV)
				return env.rp, mustJSON(t, m), request
			},
			ok: true,
		},
		{
			// An empty user handle is equivalent to an absent one.
			name: "scoped login with empty user handle",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				request, requestJSON, err := env.rp.NewLoginWithOptions(&LoginOptions{AllowCredentials: env.records})
				if err != nil {
					t.Fatal(err)
				}
				m := env.auth.loginResponse(t, testRPID, testOrigin, challengeOf(t, requestJSON), "", flagUP|flagUV)
				m["response"].(map[string]any)["userHandle"] = ""
				return env.rp, mustJSON(t, m), request
			},
			ok: true,
		},
		{
			// Malformed records are dropped from allowCredentials
			// rather than failing the ceremony.
			name: "scoped login with malformed record",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				request, requestJSON, err := env.rp.NewLoginWithOptions(&LoginOptions{
					AllowCredentials: []string{"not a passkey record", env.record},
				})
				if err != nil {
					t.Fatal(err)
				}
				var opts struct {
					AllowCredentials []credentialDescriptor `json:"allowCredentials"`
				}
				if err := json.Unmarshal(requestJSON, &opts); err != nil {
					t.Fatal(err)
				}
				wantID := base64.RawURLEncoding.EncodeToString(env.auth.credentialID)
				if len(opts.AllowCredentials) != 1 || opts.AllowCredentials[0].ID != wantID {
					t.Errorf("allowCredentials = %+v, want only %q", opts.AllowCredentials, wantID)
				}
				m := env.auth.loginResponse(t, testRPID, testOrigin, challengeOf(t, requestJSON), env.user.ID, flagUP|flagUV)
				return env.rp, mustJSON(t, m), request
			},
			ok: true,
		},
		{
			// The extension bytes are covered by the signature.
			name: "extension data",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				env.auth.extensions = []byte{0xa0}
				return env.rp, mustJSON(t, env.response(t, flagUP|flagUV)), env.request
			},
			ok: true,
		},
		{
			// Only rawId identifies the credential; the id field is
			// deliberately left pointing at the registered one.
			name: "unknown credential",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				m := withRawID(env.response(t, flagUP|flagUV), unknownID)
				return env.rp, mustJSON(t, m), env.request
			},
			errIs:  ErrUnknownCredential,
			errHas: "not registered",
		},
		{
			// The same credential registered under another RP ID: its
			// key would verify the signature, but the record is not a
			// candidate.
			name: "record for a different RP ID",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				otherRP := newTestRP(t, Options{RPID: "other.example"})
				creationJSON, err := otherRP.NewRegistration(env.user, nil)
				if err != nil {
					t.Fatal(err)
				}
				record, err := otherRP.Register(mustJSON(t, env.auth.registrationResponse(t, "other.example", testOrigin,
					challengeOf(t, creationJSON), flagUP|flagUV)))
				if err != nil {
					t.Fatal(err)
				}
				env.records = []string{record}
				return env.rp, mustJSON(t, env.response(t, flagUP|flagUV)), env.request
			},
			errIs:  ErrUnknownCredential,
			errHas: "record for a different RP ID",
		},
		{
			name: "wrong signing key",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				return env.rp, impostorResponse(t, env), env.request
			},
			errHas: "signature verification failed",
		},
		{
			name: "expired request",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				return env.rp, mustJSON(t, env.response(t, flagUP|flagUV)), expired(env)
			},
			errIs: ErrRequestExpired,
		},
		{
			name: "request not yet expired",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				recent := withRequestCreated(env.request, time.Now().Add(-4*time.Minute))
				return env.rp, mustJSON(t, env.response(t, flagUP|flagUV)), recent
			},
			ok: true,
		},
		{
			// The timeout belongs to the RelyingParty verifying the login.
			name: "expired request within a longer timeout",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				longRP := newTestRP(t, Options{Timeout: 30 * time.Minute})
				return longRP, mustJSON(t, env.response(t, flagUP|flagUV)), expired(env)
			},
			ok: true,
		},
		{
			// The request asked for it, so a conforming client would
			// not have returned this assertion: not the user's problem,
			// hence no sentinel.
			name: "user verification not performed",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				return env.rp, mustJSON(t, env.response(t, flagUP)), env.request
			},
			errHas: "client did not honor",
		},
		{
			name: "user verification optional",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				return optionalUV(t), mustJSON(t, env.response(t, flagUP)), env.request
			},
			ok: true,
		},

		// A sentinel must be unreachable when an earlier check fails.
		{
			name: "challenge mismatch masks unknown credential",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				m := env.auth.loginResponse(t, testRPID, testOrigin, otherChallenge, env.user.ID, flagUP|flagUV)
				return env.rp, mustJSON(t, withRawID(m, unknownID)), env.request
			},
			errHas: "challenge does not match",
		},
		{
			name: "wrong origin masks expiry",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				m := env.auth.loginResponse(t, testRPID, "https://attacker.example", env.challenge, env.user.ID, flagUP|flagUV)
				return env.rp, mustJSON(t, m), expired(env)
			},
			errHas: "is not the expected value",
		},
		{
			name: "unknown credential masks expiry",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				m := withRawID(env.response(t, flagUP|flagUV), unknownID)
				return env.rp, mustJSON(t, m), expired(env)
			},
			errIs: ErrUnknownCredential,
		},
		{
			name: "failed signature masks expiry",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				return env.rp, impostorResponse(t, env), expired(env)
			},
			errHas: "signature verification failed",
		},
		{
			name: "expiry masks user verification",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				return env.rp, mustJSON(t, env.response(t, flagUP)), expired(env)
			},
			errIs: ErrRequestExpired,
		},
		{
			name: "unknown credential masks user verification",
			setup: func(t *testing.T, env *loginEnv) (*RelyingParty, []byte, []byte) {
				m := withRawID(env.response(t, flagUP), unknownID)
				return env.rp, mustJSON(t, m), env.request
			},
			errIs: ErrUnknownCredential,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newLoginEnv(t)
			rp, respJSON, request := tt.setup(t, env)
			resp, err := ParseResponse(respJSON)
			if err != nil {
				t.Fatalf("ParseResponse() = %v", err)
			}
			result, err := rp.Login(resp, request, env.records)
			if tt.ok {
				if err != nil {
					t.Fatalf("Login() = %v, want success", err)
				}
				if result.Matched != 0 {
					t.Errorf("Login() matched record %d, want 0", result.Matched)
				}
				return
			}
			if result != nil {
				t.Errorf("Login() = %+v with error %v, want nil", result, err)
			}
			checkError(t, err, tt.errIs, tt.errHas)
		})
	}

	for _, origin := range lookalikeOrigins {
		t.Run("lookalike origin "+origin, func(t *testing.T) {
			env := newLoginEnv(t)
			m := env.auth.loginResponse(t, testRPID, origin, env.challenge, env.user.ID, flagUP|flagUV)
			resp, err := ParseResponse(mustJSON(t, m))
			if err != nil {
				t.Fatalf("ParseResponse() = %v", err)
			}
			_, err = env.rp.Login(resp, env.request, env.records)
			checkError(t, err, nil, "is not the expected value")
		})
	}
}

func TestLoginNilResponse(t *testing.T) {
	env := newLoginEnv(t)
	_, err := env.rp.Login(nil, env.request, env.records)
	checkError(t, err, nil, "response is nil")
}

// TestLoginUserVerification checks the user verification policy. By
// default, Login requires user verification that can be relied upon:
// the assertion's UV flag, backed by a record registered with the UV
// flag (so that user verification was set up by whoever registered the
// passkey, not by whoever later got hold of the authenticator) or with
// the BE flag (a synced passkey). With OptionalUserVerification, Login
// accepts any assertion and reports the same computation as
// LoginResult.UserVerified. LoginResult.BackedUp is the assertion's BS
// flag in either mode.
func TestLoginUserVerification(t *testing.T) {
	rp := newTestRP(t, Options{})
	optionalUV := newTestRP(t, Options{OptionalUserVerification: true})
	user := User{ID: "wxJph3ZClFxTP2xF9r2W0A", Name: "user@example.com"}
	auth := newAuthenticator(t, algES256)

	// The records differ only in their flags. Those with neither UV nor
	// BE can't come out of Register by default, but can be imported or
	// registered with OptionalUserVerification set.
	record := func(flags byte) string {
		t.Helper()
		record, err := optionalUV.Register(mustJSON(t, auth.registrationResponse(t, testRPID, testOrigin, "AA", flags)))
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	recNone := record(flagUP)
	recUV := record(flagUP | flagUV)
	recBE := record(flagUP | flagBE)
	recUVBE := record(flagUP | flagUV | flagBE | flagBS)

	tests := []struct {
		name         string
		rp           *RelyingParty
		record       string
		assertion    byte
		errIs        error
		errHas       string
		userVerified bool
		backedUp     bool
	}{
		{
			name: "UV record, UV assertion",
			rp:   rp, record: recUV, assertion: flagUP | flagUV,
			userVerified: true,
		},
		{
			// The client did not honor userVerification: "required":
			// nothing the user can fix, so no sentinel.
			name: "UV record, no UV",
			rp:   rp, record: recUV, assertion: flagUP,
			errHas: "no user verification flag",
		},
		{
			// A PIN configured after registration, possibly by a thief.
			name: "unverified record, UV assertion",
			rp:   rp, record: recNone, assertion: flagUP | flagUV,
			errIs: ErrUserVerificationUnavailable, errHas: "can't be relied upon",
		},
		{
			// The record is what makes this unfixable by the client, so
			// the user is pointed at it, not at the missing flag.
			name: "unverified record, no UV",
			rp:   rp, record: recNone, assertion: flagUP,
			errIs: ErrUserVerificationUnavailable, errHas: "neither the UV nor the BE flag",
		},
		{
			name: "synced record, UV assertion",
			rp:   rp, record: recBE, assertion: flagUP | flagUV | flagBE | flagBS,
			userVerified: true, backedUp: true,
		},
		{
			name: "synced record, no UV",
			rp:   rp, record: recBE, assertion: flagUP | flagBE | flagBS,
			errHas: "client did not honor",
		},
		{
			name: "UV synced record, UV assertion",
			rp:   rp, record: recUVBE, assertion: flagUP | flagUV | flagBE | flagBS,
			userVerified: true, backedUp: true,
		},
		{
			name: "backup eligible but not backed up",
			rp:   rp, record: recBE, assertion: flagUP | flagUV | flagBE,
			userVerified: true,
		},

		{
			name: "optional, UV record, UV assertion",
			rp:   optionalUV, record: recUV, assertion: flagUP | flagUV,
			userVerified: true,
		},
		{
			name: "optional, UV record, no UV",
			rp:   optionalUV, record: recUV, assertion: flagUP,
		},
		{
			name: "optional, unverified record, UV assertion",
			rp:   optionalUV, record: recNone, assertion: flagUP | flagUV,
		},
		{
			name: "optional, unverified record, no UV",
			rp:   optionalUV, record: recNone, assertion: flagUP,
		},
		{
			name: "optional, synced record, UV assertion",
			rp:   optionalUV, record: recBE, assertion: flagUP | flagUV | flagBE | flagBS,
			userVerified: true, backedUp: true,
		},
		{
			name: "optional, synced record, no UV",
			rp:   optionalUV, record: recBE, assertion: flagUP | flagBE | flagBS,
			backedUp: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, requestJSON, err := tt.rp.NewLogin()
			if err != nil {
				t.Fatal(err)
			}
			resp, err := ParseResponse(mustJSON(t, auth.loginResponse(t, testRPID, testOrigin,
				challengeOf(t, requestJSON), user.ID, tt.assertion)))
			if err != nil {
				t.Fatal(err)
			}
			result, err := tt.rp.Login(resp, request, []string{tt.record})
			if tt.errIs != nil || tt.errHas != "" {
				checkError(t, err, tt.errIs, tt.errHas)
				return
			}
			if err != nil {
				t.Fatalf("Login() = %v, want success", err)
			}
			want := &LoginResult{UserVerified: tt.userVerified, BackedUp: tt.backedUp}
			if *result != *want {
				t.Errorf("Login() = %+v, want %+v", result, want)
			}
		})
	}
}

// TestLoginBitFlips checks that authenticatorData, clientDataJSON, and
// the signature are all covered by signature verification: flipping any
// single bit of any of them must fail the ceremony, at ParseResponse or
// at Login.
func TestLoginBitFlips(t *testing.T) {
	env := newLoginEnv(t)
	m := env.response(t, flagUP|flagUV)

	if resp, err := ParseResponse(mustJSON(t, m)); err != nil {
		t.Fatal(err)
	} else if _, err := env.rp.Login(resp, env.request, env.records); err != nil {
		t.Fatalf("baseline Login() = %v, want success", err)
	}

	response := m["response"].(map[string]any)
	for _, field := range []string{"authenticatorData", "clientDataJSON", "signature"} {
		orig := response[field].(string)
		data, err := base64.RawURLEncoding.DecodeString(orig)
		if err != nil {
			t.Fatal(err)
		}
		for i := range data {
			for bit := range 8 {
				mutated := slices.Clone(data)
				mutated[i] ^= 1 << bit
				response[field] = base64.RawURLEncoding.EncodeToString(mutated)
				resp, err := ParseResponse(mustJSON(t, m))
				if err == nil {
					_, err = env.rp.Login(resp, env.request, env.records)
				}
				if err == nil {
					t.Errorf("%s: flipping bit %d of byte %d: ceremony succeeded", field, bit, i)
				}
			}
		}
		response[field] = orig
	}
}

// TestParseResponse exercises each ParseResponse check: every case is a
// valid, correctly signed response except for the one check under test.
func TestParseResponse(t *testing.T) {
	valid := func(t *testing.T, a *authenticator) map[string]any {
		return a.loginResponse(t, testRPID, testOrigin, testChallenge, "user-id", flagUP|flagUV)
	}
	responseField := func(m map[string]any, field string, v any) map[string]any {
		m["response"].(map[string]any)[field] = v
		return m
	}

	tests := []struct {
		name   string
		resp   func(t *testing.T, a *authenticator) []byte
		ok     bool
		errHas string
	}{
		{
			name: "valid",
			resp: func(t *testing.T, a *authenticator) []byte {
				return mustJSON(t, valid(t, a))
			},
			ok: true,
		},
		{
			name: "invalid JSON",
			resp: func(t *testing.T, a *authenticator) []byte {
				return []byte("{")
			},
			errHas: "invalid response JSON",
		},
		{
			name: "credential ID padded base64",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := valid(t, a)
				m["rawId"] = "AA=="
				return mustJSON(t, m)
			},
			errHas: "malformed credential ID",
		},
		{
			name: "credential ID standard base64",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := valid(t, a)
				m["rawId"] = "AAA+"
				return mustJSON(t, m)
			},
			errHas: "malformed credential ID",
		},
		{
			name: "credential ID with newline",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := valid(t, a)
				m["rawId"] = "AA\r\nAA"
				return mustJSON(t, m)
			},
			errHas: "malformed credential ID",
		},
		{
			name: "empty credential ID",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := valid(t, a)
				m["rawId"] = ""
				return mustJSON(t, m)
			},
			errHas: "response has no credential ID",
		},
		{
			name: "client data encoding",
			resp: func(t *testing.T, a *authenticator) []byte {
				return mustJSON(t, responseField(valid(t, a), "clientDataJSON", "!!!"))
			},
			errHas: "malformed client data encoding",
		},
		{
			name: "client data JSON",
			resp: func(t *testing.T, a *authenticator) []byte {
				notJSON := base64.RawURLEncoding.EncodeToString([]byte("not json"))
				return mustJSON(t, responseField(valid(t, a), "clientDataJSON", notJSON))
			},
			errHas: "malformed client data JSON",
		},
		{
			name: "client data type",
			resp: func(t *testing.T, a *authenticator) []byte {
				a.clientDataType = "webauthn.create"
				return mustJSON(t, valid(t, a))
			},
			errHas: `client data type is "webauthn.create"`,
		},
		{
			name: "challenge encoding",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := a.loginResponse(t, testRPID, testOrigin, "!!!", "user-id", flagUP|flagUV)
				return mustJSON(t, m)
			},
			errHas: "malformed client data encoding",
		},
		{
			name: "short challenge",
			resp: func(t *testing.T, a *authenticator) []byte {
				short := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 31))
				return mustJSON(t, a.loginResponse(t, testRPID, testOrigin, short, "user-id", flagUP|flagUV))
			},
			errHas: "malformed challenge",
		},
		{
			name: "long challenge",
			resp: func(t *testing.T, a *authenticator) []byte {
				long := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 33))
				return mustJSON(t, a.loginResponse(t, testRPID, testOrigin, long, "user-id", flagUP|flagUV))
			},
			errHas: "malformed challenge",
		},
		{
			// "AB" decodes to one byte with non-zero trailing bits,
			// which only the strict decoder rejects.
			name: "credential ID with non-canonical padding bits",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := valid(t, a)
				m["rawId"] = "AB"
				return mustJSON(t, m)
			},
			errHas: "malformed credential ID",
		},
		{
			name: "cross-origin",
			resp: func(t *testing.T, a *authenticator) []byte {
				crossOrigin := true
				a.crossOrigin = &crossOrigin
				return mustJSON(t, valid(t, a))
			},
			errHas: "cross-origin frame",
		},
		{
			name: "cross-origin absent",
			resp: func(t *testing.T, a *authenticator) []byte {
				a.crossOrigin = nil
				return mustJSON(t, valid(t, a))
			},
			ok: true,
		},
		{
			name: "top origin",
			resp: func(t *testing.T, a *authenticator) []byte {
				a.clientDataExtra = map[string]any{"topOrigin": testOrigin}
				return mustJSON(t, valid(t, a))
			},
			errHas: "cross-origin frame",
		},
		{
			name: "authenticator data encoding",
			resp: func(t *testing.T, a *authenticator) []byte {
				return mustJSON(t, responseField(valid(t, a), "authenticatorData", "!!!"))
			},
			errHas: "malformed authenticator data encoding",
		},
		{
			name: "authenticator data too short",
			resp: func(t *testing.T, a *authenticator) []byte {
				authData := a.authData(testRPID, false, flagUP|flagUV)[:36]
				clientData := a.clientDataJSON(t, "webauthn.get", testChallenge, testOrigin)
				return mustJSON(t, a.signedLoginResponse(t, authData, clientData, "user-id"))
			},
			errHas: "malformed authenticator data",
		},
		{
			name: "attested data flag",
			resp: func(t *testing.T, a *authenticator) []byte {
				return mustJSON(t, a.loginResponse(t, testRPID, testOrigin, testChallenge, "user-id", flagUP|flagUV|flagAT))
			},
			errHas: "unexpectedly has attested data",
		},
		{
			name: "extension data claimed but absent",
			resp: func(t *testing.T, a *authenticator) []byte {
				return mustJSON(t, a.loginResponse(t, testRPID, testOrigin, testChallenge, "user-id", flagUP|flagUV|flagED))
			},
			errHas: "claims extension data but has none",
		},
		{
			name: "trailing bytes without extension flag",
			resp: func(t *testing.T, a *authenticator) []byte {
				authData := append(a.authData(testRPID, false, flagUP|flagUV), 0xAA)
				clientData := a.clientDataJSON(t, "webauthn.get", testChallenge, testOrigin)
				return mustJSON(t, a.signedLoginResponse(t, authData, clientData, "user-id"))
			},
			errHas: "1 unexpected trailing bytes",
		},
		{
			name: "user presence",
			resp: func(t *testing.T, a *authenticator) []byte {
				return mustJSON(t, a.loginResponse(t, testRPID, testOrigin, testChallenge, "user-id", flagUV))
			},
			errHas: "user presence flag not set",
		},
		{
			name: "backup state without eligibility",
			resp: func(t *testing.T, a *authenticator) []byte {
				return mustJSON(t, a.loginResponse(t, testRPID, testOrigin, testChallenge, "user-id", flagUP|flagBS))
			},
			errHas: "backed up but not backup eligible",
		},
		{
			name: "backup eligible only",
			resp: func(t *testing.T, a *authenticator) []byte {
				return mustJSON(t, a.loginResponse(t, testRPID, testOrigin, testChallenge, "user-id", flagUP|flagBE))
			},
			ok: true,
		},
		{
			name: "signature encoding",
			resp: func(t *testing.T, a *authenticator) []byte {
				return mustJSON(t, responseField(valid(t, a), "signature", "!!!"))
			},
			errHas: "malformed signature",
		},
		{
			name: "user handle encoding",
			resp: func(t *testing.T, a *authenticator) []byte {
				return mustJSON(t, responseField(valid(t, a), "userHandle", "!!!"))
			},
			errHas: "malformed user ID",
		},
		{
			// Only the response to a NewLogin ceremony identifies the
			// user, so it must carry a user handle.
			name: "null user handle",
			resp: func(t *testing.T, a *authenticator) []byte {
				return mustJSON(t, responseField(valid(t, a), "userHandle", nil))
			},
			errHas: "no user handle",
		},
		{
			name: "absent user handle",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := valid(t, a)
				delete(m["response"].(map[string]any), "userHandle")
				return mustJSON(t, m)
			},
			errHas: "no user handle",
		},
		{
			// An empty string is what some clients produce for an
			// absent user handle.
			name: "empty user handle",
			resp: func(t *testing.T, a *authenticator) []byte {
				return mustJSON(t, responseField(valid(t, a), "userHandle", ""))
			},
			errHas: "no user handle",
		},
		{
			// A user-scoped ceremony disregards the user handle, so it
			// may be missing, as authenticators answering
			// allowCredentials are allowed to omit it.
			name: "scoped absent user handle",
			resp: func(t *testing.T, a *authenticator) []byte {
				return mustJSON(t, a.loginResponse(t, testRPID, testOrigin, testScopedChallenge, "", flagUP|flagUV))
			},
			ok: true,
		},
		{
			name: "scoped empty user handle",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := a.loginResponse(t, testRPID, testOrigin, testScopedChallenge, "", flagUP|flagUV)
				return mustJSON(t, responseField(m, "userHandle", ""))
			},
			ok: true,
		},
		{
			// It is still parsed, and must be well-formed.
			name: "scoped oversized user handle",
			resp: func(t *testing.T, a *authenticator) []byte {
				handle := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 65))
				m := a.loginResponse(t, testRPID, testOrigin, testScopedChallenge, "", flagUP|flagUV)
				return mustJSON(t, responseField(m, "userHandle", handle))
			},
			errHas: "invalid user ID",
		},
		{
			name: "oversized user handle",
			resp: func(t *testing.T, a *authenticator) []byte {
				handle := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 65))
				return mustJSON(t, responseField(valid(t, a), "userHandle", handle))
			},
			errHas: "invalid user ID",
		},
		{
			name: "maximum user handle",
			resp: func(t *testing.T, a *authenticator) []byte {
				handle := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 64))
				return mustJSON(t, responseField(valid(t, a), "userHandle", handle))
			},
			ok: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAuthenticator(t, algES256)
			_, err := ParseResponse(tt.resp(t, a))
			if tt.ok {
				if err != nil {
					t.Fatalf("ParseResponse() = %v, want success", err)
				}
				return
			}
			if err == nil {
				t.Fatal("ParseResponse() succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.errHas) {
				t.Errorf("ParseResponse() = %v, want it to contain %q", err, tt.errHas)
			}
		})
	}
}

// TestLoginLockouts checks that an imperfect records slice does not
// lock the user out of the account: malformed records are skipped, and
// when several records share a credential ID, Login matches the record
// whose key actually signed the assertion, wherever it is in the slice.
// Parse and signature failures are reported only when nothing matches.
func TestLoginLockouts(t *testing.T) {
	rp := newTestRP(t, Options{})
	user := User{ID: "wxJph3ZClFxTP2xF9r2W0A", Name: "user@example.com"}

	// authA and authB share a credential ID with different keys, and
	// both are registered. authC asserts the same credential ID with a
	// third, unregistered key.
	authA := newAuthenticator(t, algES256)
	authB := newAuthenticator(t, algES256)
	authB.credentialID = authA.credentialID
	authC := newAuthenticator(t, algES256)
	authC.credentialID = authA.credentialID

	register := func(rp *RelyingParty, rpID string, a *authenticator) string {
		creationJSON, err := rp.NewRegistration(user, nil)
		if err != nil {
			t.Fatal(err)
		}
		record, err := rp.Register(mustJSON(t, a.registrationResponse(t, rpID, testOrigin,
			challengeOf(t, creationJSON), flagUP|flagUV)))
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	recA, recB := register(rp, testRPID, authA), register(rp, testRPID, authB)
	// authA's credential registered under another RP ID.
	otherRP := register(newTestRP(t, Options{RPID: "other.example"}), "other.example", authA)
	malformed := "$webauthn$v=1$AAAA"

	request, requestJSON, err := rp.NewLogin()
	if err != nil {
		t.Fatal(err)
	}
	challenge := challengeOf(t, requestJSON)
	response := func(a *authenticator) *Response {
		resp, err := ParseResponse(mustJSON(t, a.loginResponse(t, testRPID, testOrigin, challenge, user.ID, flagUP|flagUV)))
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	respA, respB, respC := response(authA), response(authB), response(authC)

	tests := []struct {
		name    string
		records []string
		resp    *Response
		matched int
		errIs   error
		errHas  string
	}{
		{
			name:    "first duplicate signed",
			records: []string{recA, recB},
			resp:    respA,
			matched: 0,
		},
		{
			name:    "second duplicate signed",
			records: []string{recA, recB},
			resp:    respB,
			matched: 1,
		},
		{
			name:    "no duplicate signed",
			records: []string{recA, recB},
			resp:    respC,
			errHas:  "multiple records matched the credential ID",
		},
		{
			name:    "single record not signed",
			records: []string{recA},
			resp:    respB,
			errHas:  "signature verification failed",
		},
		{
			name:    "malformed record skipped",
			records: []string{malformed, recA},
			resp:    respA,
			matched: 1,
		},
		{
			name:    "malformed record after match",
			records: []string{recA, malformed},
			resp:    respA,
			matched: 0,
		},
		{
			name:    "malformed record and duplicates",
			records: []string{malformed, recA, recB},
			resp:    respB,
			matched: 2,
		},
		{
			name:    "only malformed records",
			records: []string{malformed},
			resp:    respA,
			errIs:   ErrUnknownCredential,
			errHas:  "were skipped",
		},
		{
			name:    "other RP ID record before match",
			records: []string{otherRP, recA},
			resp:    respA,
			matched: 1,
		},
		{
			name:    "only other RP ID record",
			records: []string{otherRP},
			resp:    respA,
			errIs:   ErrUnknownCredential,
			errHas:  "record for a different RP ID",
		},
		{
			name:    "no records",
			records: nil,
			resp:    respA,
			errIs:   ErrUnknownCredential,
			errHas:  "not registered",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := rp.Login(tt.resp, request, tt.records)
			if tt.errIs != nil || tt.errHas != "" {
				checkError(t, err, tt.errIs, tt.errHas)
				return
			}
			if err != nil {
				t.Fatalf("Login() = %v, want success", err)
			}
			if result.Matched != tt.matched {
				t.Errorf("Login() matched record %d, want %d", result.Matched, tt.matched)
			}
		})
	}
}

// TestNewLoginUserVerification checks that login ceremonies request user
// verification as "required" by default, so that clients prompt for it
// rather than return an assertion Login would reject, and as
// "preferred" with OptionalUserVerification.
func TestNewLoginUserVerification(t *testing.T) {
	env := newLoginEnv(t)
	for _, tt := range []struct {
		optional bool
		want     string
	}{
		{false, "required"},
		{true, "preferred"},
	} {
		rp := newTestRP(t, Options{OptionalUserVerification: tt.optional})
		_, unscopedJSON, err := rp.NewLogin()
		if err != nil {
			t.Fatal(err)
		}
		_, scopedJSON, err := rp.NewLoginWithOptions(&LoginOptions{AllowCredentials: env.records})
		if err != nil {
			t.Fatal(err)
		}
		for _, optionsJSON := range [][]byte{unscopedJSON, scopedJSON} {
			var o requestOptions
			if err := json.Unmarshal(optionsJSON, &o); err != nil {
				t.Fatal(err)
			}
			if o.UserVerification != tt.want {
				t.Errorf("OptionalUserVerification = %v: userVerification = %q, want %q",
					tt.optional, o.UserVerification, tt.want)
			}
		}
	}
}

func TestUserScopedLogin(t *testing.T) {
	env := newLoginEnv(t)

	// Nil options, and nil or empty AllowCredentials, begin an unscoped
	// ceremony like NewLogin does: allowCredentials is empty on the wire,
	// and the response identifies the user.
	for _, options := range []*LoginOptions{nil, {}, {AllowCredentials: []string{}}} {
		request, requestJSON, err := env.rp.NewLoginWithOptions(options)
		if err != nil {
			t.Fatalf("NewLoginWithOptions(%#v) = %v", options, err)
		}
		if !strings.Contains(string(requestJSON), `"allowCredentials":[]`) {
			t.Errorf("NewLoginWithOptions(%#v) options = %s, want an empty allowCredentials list", options, requestJSON)
		}
		m := env.auth.loginResponse(t, testRPID, testOrigin, challengeOf(t, requestJSON), env.user.ID, flagUP|flagUV)
		resp, err := ParseResponse(mustJSON(t, m))
		if err != nil {
			t.Fatalf("ParseResponse() = %v", err)
		}
		if got := resp.UnauthenticatedUserID(); got != env.user.ID {
			t.Errorf("NewLoginWithOptions(%#v): UnauthenticatedUserID() = %q, want %q", options, got, env.user.ID)
		}
		if resp.RequestID() != RequestID(request) {
			t.Errorf("NewLoginWithOptions(%#v): Response.RequestID() = %q, want %q", options, resp.RequestID(), RequestID(request))
		}
		if _, err := env.rp.Login(resp, request, env.records); err != nil {
			t.Errorf("NewLoginWithOptions(%#v): Login() = %v, want success", options, err)
		}
	}

	request, requestJSON, err := env.rp.NewLoginWithOptions(&LoginOptions{AllowCredentials: env.records})
	if err != nil {
		t.Fatal(err)
	}
	challenge := challengeOf(t, requestJSON)

	for _, handle := range []string{env.user.ID, "someone-else", ""} {
		m := env.auth.loginResponse(t, testRPID, testOrigin, challenge, handle, flagUP|flagUV)
		resp, err := ParseResponse(mustJSON(t, m))
		if err != nil {
			t.Fatalf("ParseResponse() = %v", err)
		}
		if got := resp.UnauthenticatedUserID(); got != "" {
			t.Errorf("handle %q: UnauthenticatedUserID() = %q, want empty", handle, got)
		}
		if resp.RequestID() != RequestID(request) {
			t.Errorf("handle %q: Response.RequestID() = %q, want %q", handle, resp.RequestID(), RequestID(request))
		}
		if _, err := env.rp.Login(resp, request, env.records); err != nil {
			t.Errorf("handle %q: Login() = %v, want success", handle, err)
		}
	}

	m := env.response(t, flagUP|flagUV)
	resp, err := ParseResponse(mustJSON(t, m))
	if err != nil {
		t.Fatalf("ParseResponse() = %v", err)
	}
	if got := resp.UnauthenticatedUserID(); got != env.user.ID {
		t.Errorf("unscoped: UnauthenticatedUserID() = %q, want %q", got, env.user.ID)
	}

	// The kind is a byte of the challenge: a response carrying the other
	// one, however well signed, no longer answers the request. It passes
	// for the other kind of ceremony only until Login.
	otherKind := func(t *testing.T, challenge string) string {
		b, err := base64.RawURLEncoding.DecodeString(challenge)
		if err != nil {
			t.Fatal(err)
		}
		if b[0] == challengeUserScoped {
			b[0] = challengeUnscoped
		} else {
			b[0] = challengeUserScoped
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	m = env.auth.loginResponse(t, testRPID, testOrigin, otherKind(t, challenge), env.user.ID, flagUP|flagUV)
	resp, err = ParseResponse(mustJSON(t, m))
	if err != nil {
		t.Fatalf("ParseResponse() = %v", err)
	}
	if got := resp.UnauthenticatedUserID(); got != env.user.ID {
		t.Errorf("scoped response marked unscoped: UnauthenticatedUserID() = %q, want %q", got, env.user.ID)
	}
	if resp.RequestID() == RequestID(request) {
		t.Error("scoped response marked unscoped: Response.RequestID() still identifies the request")
	}
	_, err = env.rp.Login(resp, request, env.records)
	checkError(t, err, nil, "challenge does not match")

	m = env.auth.loginResponse(t, testRPID, testOrigin, otherKind(t, env.challenge), env.user.ID, flagUP|flagUV)
	resp, err = ParseResponse(mustJSON(t, m))
	if err != nil {
		t.Fatalf("ParseResponse() = %v", err)
	}
	if got := resp.UnauthenticatedUserID(); got != "" {
		t.Errorf("unscoped response marked scoped: UnauthenticatedUserID() = %q, want empty", got)
	}
	if resp.RequestID() == RequestID(env.request) {
		t.Error("unscoped response marked scoped: Response.RequestID() still identifies the request")
	}
	_, err = env.rp.Login(resp, env.request, env.records)
	checkError(t, err, nil, "challenge does not match")
}
