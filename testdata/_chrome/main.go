// Command chrome records WebAuthn ceremonies performed by Chrome, against
// virtual authenticators driven through its DevTools protocol, so that
// the package tests can replay them without a browser.
//
// It is a separate module, so that its dependencies stay out of
// filippo.io/passkey. Run it from the repository root with
//
//	go run -C testdata/_chrome .
//
// to rewrite testdata/chrome.json, then check the result with
//
//	go test -run TestChromeRecordings
//
// It needs a Chrome binary, found on $PATH or in one of the usual
// locations, and permission to bind a loopback port and launch it.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"time"

	"filippo.io/passkey"
	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
)

// recordings is the format of testdata/chrome.json: a relying party, a
// user, and one recording per authenticator.
type recordings struct {
	// Browser is the product string of the Chrome that performed the
	// ceremonies.
	Browser string `json:"browser"`
	RPID    string `json:"rpId"`
	Origin  string `json:"origin"`
	UserID  string `json:"userId"`
	// Recordings are the ceremonies, one authenticator each. The user
	// holds all their credentials at once.
	Recordings []recording `json:"recordings"`
}

// recording is a registration and the logins that followed it, all
// performed by the same virtual authenticator, along with the values the
// authenticator was configured to report.
type recording struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// AAGUID and CredentialID are read out of the registration
	// response, and Transports and BackedUp are how the authenticator
	// was configured, all as expected of the record.
	AAGUID       string   `json:"aaguid"`       // hex
	CredentialID string   `json:"credentialId"` // hex
	Transports   []string `json:"transports"`
	BackedUp     bool     `json:"backedUp"`
	Registration struct {
		// Options is the PublicKeyCredentialCreationOptions passed to
		// navigator.credentials.create(), and Response the toJSON()
		// serialization of what it returned.
		Options  json.RawMessage `json:"options"`
		Response json.RawMessage `json:"response"`
	} `json:"registration"`
	Logins []login `json:"logins"`
}

// login is a login ceremony: the request value the application would
// have stored, the PublicKeyCredentialRequestOptions passed to
// navigator.credentials.get(), and the toJSON() serialization of what it
// returned, along with the flags the authenticator was configured to
// report and, for responses the authenticator was configured to break,
// the reason they must be rejected.
type login struct {
	Request      string          `json:"request"` // hex
	Options      json.RawMessage `json:"options"`
	Response     json.RawMessage `json:"response"`
	UserVerified bool            `json:"userVerified"`
	BackedUp     bool            `json:"backedUp"`
	Error        string          `json:"error,omitempty"`
}

// The reasons a recorded login must be rejected for.
const (
	errorUserPresence = "user-presence" // the user presence flag is clear
	errorSignature    = "signature"     // the signature is bogus
)

func main() {
	log.SetFlags(0)
	output := flag.String("o", "../chrome.json", "file to write the recordings to")
	flag.Parse()

	s := newSession()
	defer s.close()

	// A platform authenticator with user verification, and the shape of
	// the counter incrementing across logins. The last login is
	// user-scoped: it answers a NewLoginForUser ceremony.
	a := s.addAuthenticator("platform",
		"A CTAP2.1 platform authenticator with user verification, "+
			"whose credentials are not backup eligible; "+
			"the last login is user-scoped.",
		platformAuthenticator(), nil)
	a.register()
	a.login()
	a.login()
	a.loginForUser()
	// Chrome must honor excludeCredentials: an authenticator that holds
	// one of the excluded credentials refuses to create another.
	if _, _, err := a.create([]string{a.record}); err == nil {
		s.fatalf("a registration excluding the authenticator's credential succeeded")
	} else if got := exceptionName(err); got != "InvalidStateError" {
		s.fatalf("registration with an excluded credential failed with %v, want InvalidStateError", err)
	} else {
		log.Printf("excluded credential refused by the client, as expected: %v", err)
	}
	a.close()

	// Backup flags: a synced credential, and one that gets synced after
	// its registration.
	opts := platformAuthenticator()
	opts.DefaultBackupEligibility = true
	opts.DefaultBackupState = true
	a = s.addAuthenticator("synced",
		"A CTAP2.1 platform authenticator whose credentials are "+
			"backup eligible and backed up.", opts, nil)
	a.register()
	a.login()
	a.close()

	opts = platformAuthenticator()
	opts.DefaultBackupEligibility = true
	a = s.addAuthenticator("backup-eligible",
		"A CTAP2.1 platform authenticator whose credentials are "+
			"backup eligible but not backed up; the credential is "+
			"backed up between the first and the second login.", opts, nil)
	a.register()
	a.login()
	a.setBackupState(true)
	a.login()
	a.close()

	// A roaming authenticator, for which Chrome zeroes the AAGUID.
	opts = platformAuthenticator()
	opts.Transport = webauthn.AuthenticatorTransportUsb
	a = s.addAuthenticator("security-key",
		"A CTAP2.1 USB authenticator with user verification.", opts, nil)
	a.register()
	a.login()
	a.close()

	// Responses altered by the response override bits of the DevTools
	// protocol, which clear the user verification or user presence flag,
	// or zero the signature, in every response. (Chrome won't create a
	// discoverable credential on an authenticator that can't verify the
	// user, so clearing the flag is the only way to record an assertion
	// without user verification.)
	a = s.addAuthenticator("no-user-verification",
		"A CTAP2.1 platform authenticator that clears the user "+
			"verification flag in every response.", platformAuthenticator(),
		webauthn.SetResponseOverrideBits("").WithIsBadUV(true))
	a.register()
	a.login()
	a.close()

	a = s.addAuthenticator("no-user-presence",
		"A CTAP2.1 platform authenticator that clears the user presence "+
			"flag in every response.", platformAuthenticator(),
		webauthn.SetResponseOverrideBits("").WithIsBadUP(true))
	a.register()
	a.login()
	a.close()

	a = s.addAuthenticator("bogus-signature",
		"A CTAP2.1 platform authenticator whose assertion signatures "+
			"are zeroed.", platformAuthenticator(),
		webauthn.SetResponseOverrideBits("").WithIsBogusSignature(true))
	a.register()
	a.login()
	a.close()

	// Chrome must honor residentKey: "required", which a U2F
	// authenticator can't satisfy.
	a = s.addAuthenticator("u2f", "", &webauthn.VirtualAuthenticatorOptions{
		Protocol:                    webauthn.AuthenticatorProtocolU2f,
		Transport:                   webauthn.AuthenticatorTransportUsb,
		AutomaticPresenceSimulation: true,
	}, nil)
	if _, _, err := a.create(nil); err == nil {
		s.fatalf("a U2F authenticator created a discoverable credential")
	} else if got := exceptionName(err); got != "NotAllowedError" {
		s.fatalf("U2F registration failed with %v, want NotAllowedError", err)
	} else {
		log.Printf("U2F registration refused by the client, as expected: %v", err)
	}
	a.discard()

	s.write(*output)
}

// platformAuthenticator returns the options of a CTAP2.1 platform
// authenticator that verifies the user and creates credentials that are
// not backup eligible.
func platformAuthenticator() *webauthn.VirtualAuthenticatorOptions {
	return &webauthn.VirtualAuthenticatorOptions{
		Protocol:                    webauthn.AuthenticatorProtocolCtap2,
		Ctap2version:                webauthn.Ctap2versionCtap21,
		Transport:                   webauthn.AuthenticatorTransportInternal,
		HasResidentKey:              true,
		HasUserVerification:         true,
		IsUserVerified:              true,
		AutomaticPresenceSimulation: true,
	}
}

// chromePaths are the usual locations of a Chrome binary, tried after $PATH.
var chromePaths = []string{
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	"/Applications/Chromium.app/Contents/MacOS/Chromium",
	"/usr/bin/google-chrome",
	"/usr/bin/chromium",
	"/usr/bin/chromium-browser",
}

func findChrome() string {
	for _, name := range []string{"google-chrome", "chromium", "chromium-browser", "chrome"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	for _, path := range chromePaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	log.Fatal("no Chrome binary found")
	return ""
}

// pageHTML is the document the ceremonies run in. It only needs to exist
// at the right origin: the ceremonies are driven by evaluating JavaScript
// in it.
const pageHTML = `<!doctype html><meta charset=utf-8><title>passkey recordings</title>`

// session is a relying party, an HTTP server serving pageHTML at its
// origin, and a Chrome pointed at it.
type session struct {
	rp   *passkey.RelyingParty
	user passkey.User
	url  string

	server *httptest.Server
	ctx    context.Context // the browser
	cancel context.CancelFunc

	out recordings
}

// newSession starts the server and Chrome. localhost is a secure
// context, so ceremonies are allowed over plain HTTP.
func newSession() *session {
	chromePath := findChrome()

	// Bind to 127.0.0.1 but serve as localhost: an IP address is not a
	// valid RP ID, and Chrome is told to resolve localhost to the same
	// address.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	server := &httptest.Server{
		Listener: listener,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, pageHTML)
		})},
	}
	server.Start()
	port := listener.Addr().(*net.TCPAddr).Port
	origin := fmt.Sprintf("http://localhost:%d", port)

	rp, err := passkey.NewRelyingParty(&passkey.Options{RPID: "localhost", Origin: origin})
	if err != nil {
		log.Fatal(err)
	}

	allocatorOpts := append([]chromedp.ExecAllocatorOption{},
		chromedp.DefaultExecAllocatorOptions[:]...)
	allocatorOpts = append(allocatorOpts,
		chromedp.ExecPath(chromePath),
		chromedp.Flag("host-resolver-rules", "MAP localhost 127.0.0.1"),
	)
	ctx, cancelAllocator := chromedp.NewExecAllocator(context.Background(), allocatorOpts...)
	ctx, cancelBrowser := chromedp.NewContext(ctx)
	ctx, cancelTimeout := context.WithTimeout(ctx, 2*time.Minute)
	cancel := func() {
		cancelTimeout()
		cancelBrowser()
		cancelAllocator()
	}

	// Start the browser, and read its version.
	var product string
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		_, product, _, _, _, err = browser.GetVersion().Do(ctx)
		return err
	})); err != nil {
		cancel()
		log.Fatal(err)
	}
	log.Printf("recording with %s at %s", product, origin)

	s := &session{
		rp:     rp,
		user:   passkey.User{ID: rand.Text(), Name: "user@example.com"},
		url:    origin + "/",
		server: server,
		ctx:    ctx,
		cancel: cancel,
	}
	s.out.Browser = product
	s.out.RPID = "localhost"
	s.out.Origin = origin
	s.out.UserID = s.user.ID
	return s
}

func (s *session) close() {
	s.cancel()
	s.server.Close()
}

// fatalf logs a message and exits, closing Chrome first: it is not
// killed with the process.
func (s *session) fatalf(format string, v ...any) {
	log.Printf(format, v...)
	s.close()
	os.Exit(1)
}

// write writes the recordings to path.
func (s *session) write(path string) {
	encoded, err := json.MarshalIndent(s.out, "", "\t")
	if err != nil {
		s.fatalf("%v", err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		s.fatalf("%v", err)
	}
	log.Printf("wrote %d recordings to %s", len(s.out.Recordings), path)
}

// authenticator is a virtual authenticator in a tab of its own, and the
// recording of the ceremonies it performs.
type authenticator struct {
	s      *session
	ctx    context.Context // the tab
	cancel context.CancelFunc
	id     webauthn.AuthenticatorID
	opts   *webauthn.VirtualAuthenticatorOptions
	// overrides are the response override bits set on the authenticator,
	// if any.
	overrides *webauthn.SetResponseOverrideBitsParams

	rec *recording
	// record is the passkey record of the registered credential,
	// credentialID its credential ID, and backedUp its current backup
	// state.
	record       string
	credentialID []byte
	backedUp     bool
}

// addAuthenticator opens a tab on the page and adds a virtual
// authenticator to it, with the given options and response overrides.
// The tab is scoped to the authenticator, so that a login ceremony sees
// exactly one authenticator: it is closed by close or discard.
func (s *session) addAuthenticator(name, description string, opts *webauthn.VirtualAuthenticatorOptions,
	overrides *webauthn.SetResponseOverrideBitsParams) *authenticator {
	ctx, cancel := chromedp.NewContext(s.ctx)
	a := &authenticator{
		s:         s,
		ctx:       ctx,
		cancel:    cancel,
		opts:      opts,
		overrides: overrides,
		backedUp:  opts.DefaultBackupState,
		rec: &recording{
			Name:        name,
			Description: description,
			Transports:  []string{string(opts.Transport)},
			BackedUp:    opts.DefaultBackupState,
		},
	}
	if err := chromedp.Run(ctx,
		chromedp.Navigate(s.url),
		chromedp.ActionFunc(func(ctx context.Context) error {
			// WebAuthn ceremonies require the document to be focused,
			// which a background tab is not.
			if err := page.BringToFront().Do(ctx); err != nil {
				return fmt.Errorf("focusing the tab: %w", err)
			}
			if err := webauthn.Enable().Do(ctx); err != nil {
				return fmt.Errorf("enabling the WebAuthn domain: %w", err)
			}
			id, err := webauthn.AddVirtualAuthenticator(opts).Do(ctx)
			if err != nil {
				return fmt.Errorf("adding a virtual authenticator: %w", err)
			}
			a.id = id
			if overrides != nil {
				overrides.AuthenticatorID = id
				if err := overrides.Do(ctx); err != nil {
					return fmt.Errorf("setting the response overrides: %w", err)
				}
			}
			return nil
		}),
	); err != nil {
		s.fatalf("%s: %v", name, err)
	}
	return a
}

// close closes the tab and keeps the recording.
func (a *authenticator) close() {
	a.s.out.Recordings = append(a.s.out.Recordings, *a.rec)
	a.cancel()
}

// discard closes the tab and drops the recording.
func (a *authenticator) discard() {
	a.cancel()
}

// eval evaluates an async JavaScript expression in the tab and returns
// its result. If the expression throws, the error is the exception.
func (a *authenticator) eval(js string) (string, error) {
	var out string
	err := chromedp.Run(a.ctx, chromedp.Evaluate(js, &out,
		func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
			return p.WithAwaitPromise(true)
		}))
	return out, err
}

// exceptionName returns the name of a JavaScript exception. Protocol and
// context errors return an empty name.
func exceptionName(err error) string {
	var details *runtime.ExceptionDetails
	if !errors.As(err, &details) || details.Exception == nil {
		return ""
	}
	name, _, _ := strings.Cut(details.Exception.Description, ":")
	return name
}

// create runs a registration ceremony in the tab, excluding the given
// passkeys, and returns the creation options along with the serialized
// response, exactly as PublicKeyCredential.toJSON() produced it.
func (a *authenticator) create(passkeys []string) (optionsJSON, responseJSON []byte, err error) {
	optionsJSON, err = a.s.rp.NewRegistration(a.s.user, passkeys)
	if err != nil {
		a.s.fatalf("%v", err)
	}
	response, err := a.eval(fmt.Sprintf(`(async () => {
		const options = PublicKeyCredential.parseCreationOptionsFromJSON(%s);
		const credential = await navigator.credentials.create({publicKey: options});
		return JSON.stringify(credential.toJSON());
	})()`, optionsJSON))
	return optionsJSON, []byte(response), err
}

// get runs a login ceremony in the tab for the given options and returns
// the serialized response, exactly as PublicKeyCredential.toJSON()
// produced it.
func (a *authenticator) get(optionsJSON []byte) ([]byte, error) {
	response, err := a.eval(fmt.Sprintf(`(async () => {
		const options = PublicKeyCredential.parseRequestOptionsFromJSON(%s);
		const assertion = await navigator.credentials.get({publicKey: options});
		return JSON.stringify(assertion.toJSON());
	})()`, optionsJSON))
	return []byte(response), err
}

// register registers a credential and records the exchange.
func (a *authenticator) register() {
	optionsJSON, responseJSON, err := a.create(nil)
	if err != nil {
		a.s.fatalf("%s: registration: %v", a.rec.Name, err)
	}
	// The record is needed to build excludeCredentials and
	// allowCredentials, so Register has to succeed here as well as at
	// replay time.
	record, err := a.s.rp.Register(responseJSON)
	if err != nil {
		a.s.fatalf("%s: Register: %v\n%s", a.rec.Name, err, responseJSON)
	}
	a.record = record

	var resp struct {
		RawID    string `json:"rawId"`
		Response struct {
			AuthenticatorData string `json:"authenticatorData"`
		} `json:"response"`
	}
	if err := json.Unmarshal(responseJSON, &resp); err != nil {
		a.s.fatalf("%v", err)
	}
	a.credentialID = a.decode(resp.RawID)
	// The AAGUID follows the RP ID hash, the flags, and the counter.
	aaguid := a.decode(resp.Response.AuthenticatorData)[32+1+4:][:16]

	a.rec.AAGUID = hex.EncodeToString(aaguid)
	a.rec.CredentialID = hex.EncodeToString(a.credentialID)
	a.rec.Registration.Options = optionsJSON
	a.rec.Registration.Response = responseJSON
	log.Printf("%s: registered %s", a.rec.Name, record)
}

// login runs a login ceremony and records the exchange.
func (a *authenticator) login() {
	request, optionsJSON, err := a.s.rp.NewLogin()
	if err != nil {
		a.s.fatalf("%v", err)
	}
	a.recordLogin(request, optionsJSON)
}

// loginForUser runs a user-scoped login ceremony and records the
// exchange.
func (a *authenticator) loginForUser() {
	request, optionsJSON, err := a.s.rp.NewLoginForUser(a.s.user.ID, []string{a.record})
	if err != nil {
		a.s.fatalf("%v", err)
	}
	a.recordLogin(request, optionsJSON)
}

func (a *authenticator) recordLogin(request, optionsJSON []byte) {
	responseJSON, err := a.get(optionsJSON)
	if err != nil {
		a.s.fatalf("%s: login: %v", a.rec.Name, err)
	}
	l := login{
		Request:      hex.EncodeToString(request),
		Options:      optionsJSON,
		Response:     responseJSON,
		UserVerified: a.opts.HasUserVerification && a.opts.IsUserVerified,
		BackedUp:     a.backedUp,
	}
	if a.overrides != nil {
		if a.overrides.IsBadUV {
			l.UserVerified = false
		}
		switch {
		case a.overrides.IsBadUP:
			l.Error = errorUserPresence
		case a.overrides.IsBogusSignature:
			l.Error = errorSignature
		}
	}
	a.rec.Logins = append(a.rec.Logins, l)
	log.Printf("%s: login %d recorded", a.rec.Name, len(a.rec.Logins))
}

// setBackupState changes the backup state the credential reports.
func (a *authenticator) setBackupState(backedUp bool) {
	if err := chromedp.Run(a.ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		// DevTools protocol binary parameters are standard, padded
		// base64, not the base64url of the WebAuthn JSON serialization.
		return webauthn.SetCredentialProperties(a.id, base64.StdEncoding.EncodeToString(a.credentialID)).
			WithBackupEligibility(a.opts.DefaultBackupEligibility).
			WithBackupState(backedUp).Do(ctx)
	})); err != nil {
		a.s.fatalf("%s: setting the backup state: %v", a.rec.Name, err)
	}
	a.backedUp = backedUp
}

// decode decodes a base64url field of the WebAuthn JSON serialization.
func (a *authenticator) decode(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		a.s.fatalf("%v", err)
	}
	return b
}
