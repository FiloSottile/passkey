package passkey

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"
)

// This file tests against replays of ceremonies performed by Chrome's testing
// authenticator, and captured through its DevTools protocol by testdata/_chrome.

// chromeRecordings is testdata/chrome.json.
type chromeRecordings struct {
	Browser    string            `json:"browser"`
	RPID       string            `json:"rpId"`
	Origin     string            `json:"origin"`
	UserID     string            `json:"userId"`
	Recordings []chromeRecording `json:"recordings"`
}

// chromeRecording is a registration and the logins that followed it,
// performed by one authenticator.
type chromeRecording struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	AAGUID         hexBytes `json:"aaguid"`
	CredentialID   hexBytes `json:"credentialId"`
	Transports     []string `json:"transports"`
	UserVerified   bool     `json:"userVerified"`
	BackupEligible bool     `json:"backupEligible"`
	BackedUp       bool     `json:"backedUp"`
	Registration   struct {
		Options  json.RawMessage `json:"options"`
		Response json.RawMessage `json:"response"`
	} `json:"registration"`
	Logins []chromeLogin `json:"logins"`
}

// chromeLogin is a login ceremony: the stored request, the request
// options, and the response, along with whether it was begun with
// NewLoginWithCredentials, the flags it must report and, if the authenticator
// was configured to break it, why it must be rejected.
type chromeLogin struct {
	Request      hexBytes        `json:"request"`
	Options      json.RawMessage `json:"options"`
	Response     json.RawMessage `json:"response"`
	UserScoped   bool            `json:"userScoped"`
	UserVerified bool            `json:"userVerified"`
	BackedUp     bool            `json:"backedUp"`
	Error        string          `json:"error"`
}

// The reasons a recorded login is rejected for.
const (
	chromeErrorUserPresence = "user-presence" // ParseResponse rejects it
	chromeErrorSignature    = "signature"     // Login fails, without a sentinel
)

// loadChromeRecordings reads testdata/chrome.json.
func loadChromeRecordings(t testing.TB) chromeRecordings {
	t.Helper()
	data, err := os.ReadFile("testdata/chrome.json")
	if err != nil {
		t.Fatalf("%v (regenerate with go run -C testdata/_chrome .)", err)
	}
	var f chromeRecordings
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestChromeRecordings replays the recorded Chrome ceremonies: every
// registration must produce a record carrying the recorded values, and
// every login must verify against the user's records, matching its own,
// unless it was recorded broken. The recordings were made with
// OptionalUserVerification set, so that responses without user
// verification could be captured; they are replayed under both policies,
// with the default one accepting exactly the ceremonies whose flags allow
// it. Every login is also verified with a stale request, and with its
// own record deleted, so that the sentinels are reached by a real
// client's response.
func TestChromeRecordings(t *testing.T) {
	f := loadChromeRecordings(t)
	rp := newTestRP(t, Options{RPID: f.RPID, Origin: f.Origin})
	optionalUV := newTestRP(t, Options{RPID: f.RPID, Origin: f.Origin, OptionalUserVerification: true})

	var records []string
	for _, rec := range f.Recordings {
		record, err := optionalUV.Register(rec.Registration.Response)
		if err != nil {
			t.Fatalf("%s: Register() = %v, want success", rec.Name, err)
		}
		records = append(records, record)

		// The attestation object alone yields the same record.
		if got, err := optionalUV.Register(attestationObjectOnly(t, rec.Registration.Response)); err != nil || got != record {
			t.Errorf("%s: Register() from attestationObject = %q, %v, want %q", rec.Name, got, err, record)
		}

		// By default, only registrations with the UV or BE flag are accepted.
		strict, err := rp.Register(rec.Registration.Response)
		if rec.UserVerified || rec.BackupEligible {
			if err != nil || strict != record {
				t.Errorf("%s: Register() by default = %q, %v, want %q", rec.Name, strict, err, record)
			}
		} else {
			checkError(t, err, ErrUserVerificationUnavailable, "")
		}
	}

	for i, rec := range f.Recordings {
		t.Run(rec.Name, func(t *testing.T) {
			record := records[i]
			if aaguid, err := AAGUID(record); err != nil || !bytes.Equal(aaguid[:], rec.AAGUID) {
				t.Errorf("AAGUID() = %x, %v, want %x", aaguid, err, rec.AAGUID)
			}
			r := mustParseRecord(t, record)
			if !slices.Equal(r.transports, rec.Transports) {
				t.Errorf("transports = %q, want %q", r.transports, rec.Transports)
			}
			if backedUp := r.flags.backupState(); backedUp != rec.BackedUp {
				t.Errorf("backup state = %v, want %v", backedUp, rec.BackedUp)
			}
			if !bytes.Equal(r.credentialID, rec.CredentialID) {
				t.Errorf("credentialID = %x, want %x", r.credentialID, rec.CredentialID)
			}
			if r.flags.userVerified() != rec.UserVerified {
				t.Errorf("record UV flag = %v, want %v", r.flags.userVerified(), rec.UserVerified)
			}
			if r.flags.backupEligible() != rec.BackupEligible {
				t.Errorf("record BE flag = %v, want %v", r.flags.backupEligible(), rec.BackupEligible)
			}

			for j, login := range rec.Logins {
				t.Run(fmt.Sprintf("login%d", j), func(t *testing.T) {
					resp, err := ParseResponse(login.Response)
					if login.Error == chromeErrorUserPresence {
						checkError(t, err, nil, "user presence flag not set")
						return
					}
					if err != nil {
						t.Fatalf("ParseResponse() = %v, want success", err)
					}
					if resp.RequestID() != RequestID(login.Request) {
						t.Errorf("Response.RequestID() = %q, want %q", resp.RequestID(), RequestID(login.Request))
					}
					// Chrome asserts the user handle even when
					// answering allowCredentials, but a user-scoped
					// ceremony does not expose it.
					wantUserID := f.UserID
					if login.UserScoped {
						wantUserID = ""
					}
					if resp.UnauthenticatedUserID() != wantUserID {
						t.Errorf("UnauthenticatedUserID() = %q, want %q", resp.UnauthenticatedUserID(), wantUserID)
					}

					// The recording is older than any timeout, so the
					// request is verified as if it had just been created,
					// and separately as stale.
					request := withRequestCreated(login.Request, time.Now())
					stale := withRequestCreated(login.Request, time.Now().Add(-24*time.Hour))

					switch login.Error {
					case chromeErrorSignature:
						_, err := optionalUV.Login(resp, request, records)
						checkError(t, err, nil, "signature verification failed")
						return
					case "":
					default:
						t.Fatalf("unknown error reason %q", login.Error)
					}

					result, err := optionalUV.Login(resp, request, records)
					if err != nil {
						t.Fatalf("Login() = %v, want success", err)
					}
					// The assertion's UV flag is relied upon only if the
					// record was registered with UV or BE.
					want := &LoginResult{
						Matched:      i,
						UserVerified: login.UserVerified && (rec.UserVerified || rec.BackupEligible),
						BackedUp:     login.BackedUp,
					}
					if *result != *want {
						t.Errorf("Login() = %+v, want %+v", result, want)
					}

					// By default, Login requires reliable user verification:
					// a record that can't back it is the user's to fix, an
					// assertion missing the flag despite it is not.
					strict, err := rp.Login(resp, request, records)
					switch {
					case want.UserVerified:
						if err != nil || *strict != *want {
							t.Errorf("Login() by default = %+v, %v, want %+v", strict, err, want)
						}
					case rec.UserVerified || rec.BackupEligible:
						checkError(t, err, nil, "client did not honor")
					default:
						checkError(t, err, ErrUserVerificationUnavailable, "")
					}

					_, err = optionalUV.Login(resp, stale, records)
					checkError(t, err, ErrRequestExpired, "")

					// The passkey was deleted from the account.
					_, err = optionalUV.Login(resp, request, slices.Concat(records[:i], records[i+1:]))
					checkError(t, err, ErrUnknownCredential, "")
				})
			}
		})
	}
}
