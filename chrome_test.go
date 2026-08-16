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
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	AAGUID       hexBytes `json:"aaguid"`
	CredentialID hexBytes `json:"credentialId"`
	Transports   []string `json:"transports"`
	BackedUp     bool     `json:"backedUp"`
	Registration struct {
		Options  json.RawMessage `json:"options"`
		Response json.RawMessage `json:"response"`
	} `json:"registration"`
	Logins []chromeLogin `json:"logins"`
}

// chromeLogin is a login ceremony: the stored request, the request
// options, and the response, along with the flags it must report and,
// if the authenticator was configured to break it, why it must be
// rejected.
type chromeLogin struct {
	Request      hexBytes        `json:"request"`
	Options      json.RawMessage `json:"options"`
	Response     json.RawMessage `json:"response"`
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
// unless it was recorded broken. Every login is also verified against a
// relying party requiring user verification, with a stale request, and
// with its own record deleted, so that the sentinels are reached by a
// real client's response.
func TestChromeRecordings(t *testing.T) {
	f := loadChromeRecordings(t)
	rp := newTestRP(t, Options{RPID: f.RPID, Origin: f.Origin})
	uvRP := newTestRP(t, Options{RPID: f.RPID, Origin: f.Origin, RequireUserVerification: true})

	var records []string
	for _, rec := range f.Recordings {
		record, err := rp.Register(rec.Registration.Response)
		if err != nil {
			t.Fatalf("%s: Register() = %v, want success", rec.Name, err)
		}
		records = append(records, record)

		// The attestation object alone yields the same record.
		if got, err := rp.Register(attestationObjectOnly(t, rec.Registration.Response)); err != nil || got != record {
			t.Errorf("%s: Register() from attestationObject = %q, %v, want %q", rec.Name, got, err, record)
		}
	}

	for i, rec := range f.Recordings {
		t.Run(rec.Name, func(t *testing.T) {
			record := records[i]
			if aaguid, err := AAGUID(record); err != nil || !bytes.Equal(aaguid[:], rec.AAGUID) {
				t.Errorf("AAGUID() = %x, %v, want %x", aaguid, err, rec.AAGUID)
			}
			if backedUp, err := BackedUp(record); err != nil || backedUp != rec.BackedUp {
				t.Errorf("BackedUp() = %v, %v, want %v", backedUp, err, rec.BackedUp)
			}
			if transports, err := Transports(record); err != nil || !slices.Equal(transports, rec.Transports) {
				t.Errorf("Transports() = %q, %v, want %q", transports, err, rec.Transports)
			}
			// The credential ID has no exported accessor.
			if r, err := parseRecord(record); err != nil {
				t.Fatal(err)
			} else if !bytes.Equal(r.credentialID, rec.CredentialID) {
				t.Errorf("credentialID = %x, want %x", r.credentialID, rec.CredentialID)
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
					if resp.UnauthenticatedUserID() != f.UserID {
						t.Errorf("UnauthenticatedUserID() = %q, want %q", resp.UnauthenticatedUserID(), f.UserID)
					}
					if resp.UserVerified() != login.UserVerified {
						t.Errorf("UserVerified() = %v, want %v", resp.UserVerified(), login.UserVerified)
					}
					if resp.BackedUp() != login.BackedUp {
						t.Errorf("BackedUp() = %v, want %v", resp.BackedUp(), login.BackedUp)
					}

					// The recording is older than any timeout, so the
					// request is verified as if it had just been created,
					// and separately as stale.
					request := withRequestCreated(login.Request, time.Now())
					stale := withRequestCreated(login.Request, time.Now().Add(-24*time.Hour))

					switch login.Error {
					case chromeErrorSignature:
						_, err := rp.Login(resp, request, records)
						checkError(t, err, nil, "signature verification failed")
						return
					case "":
					default:
						t.Fatalf("unknown error reason %q", login.Error)
					}

					matched, err := rp.Login(resp, request, records)
					if err != nil {
						t.Fatalf("Login() = %v, want success", err)
					}
					if matched != i {
						t.Errorf("Login() matched record %d, want %d", matched, i)
					}

					_, err = uvRP.Login(resp, request, records)
					if login.UserVerified {
						if err != nil {
							t.Errorf("Login() with RequireUserVerification = %v, want success", err)
						}
					} else {
						checkError(t, err, ErrUserVerificationRequired, "")
					}

					_, err = rp.Login(resp, stale, records)
					checkError(t, err, ErrRequestExpired, "")

					// The passkey was deleted from the account.
					_, err = rp.Login(resp, request, slices.Concat(records[:i], records[i+1:]))
					checkError(t, err, ErrUnknownCredential, "")
				})
			}
		})
	}
}
