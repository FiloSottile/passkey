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
	"slices"
	"strings"
	"time"

	"filippo.io/passkey"
	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
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
	// AAGUID, CredentialID, and Transports are read out of the
	// registration response (the transports as the record stores them,
	// sorted and deduplicated), and UserVerified, BackupEligible, and
	// BackedUp are how the authenticator was configured at
	// registration, all as expected of the record.
	AAGUID         string   `json:"aaguid"`       // hex
	CredentialID   string   `json:"credentialId"` // hex
	Transports     []string `json:"transports"`
	UserVerified   bool     `json:"userVerified"`
	BackupEligible bool     `json:"backupEligible"`
	BackedUp       bool     `json:"backedUp"`
	Registration   struct {
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
// returned, along with whether the ceremony was initiated with
// LoginOptions.AllowCredentials, the flags the authenticator was
// configured to report at the time and, for responses the authenticator
// was configured to break, the reason they must be rejected.
type login struct {
	Request      string          `json:"request"` // hex
	Options      json.RawMessage `json:"options"`
	Response     json.RawMessage `json:"response"`
	UserScoped   bool            `json:"userScoped,omitempty"`
	UserVerified bool            `json:"userVerified"`
	BackedUp     bool            `json:"backedUp"`
	Error        string          `json:"error,omitempty"`
}

// The reasons a recorded login must be rejected for.
const (
	errorUserPresence = "user-presence" // the user presence flag is clear
	errorSignature    = "signature"     // the signature is bogus
	errorBackupState  = "backup-state"  // backed up, but not backup eligible
)

func main() {
	log.SetFlags(0)
	output := flag.String("o", "../chrome.json", "file to write the recordings to")
	flag.Parse()

	s := newSession()
	defer s.close()

	// A platform authenticator with user verification, and the shape of
	// the counter incrementing across logins, then reset. The third
	// login is user-scoped: it answers a ceremony begun with
	// LoginOptions.AllowCredentials.
	a := s.addAuthenticator("platform",
		"A CTAP2.1 platform authenticator with user verification, "+
			"whose credentials are not backup eligible; "+
			"the third login is user-scoped, and the signature counter "+
			"is reset to zero before the last.",
		platformAuthenticator())
	a.register()
	a.login()
	a.login()
	a.loginWithCredentials()
	a.setSignCount(0)
	a.login()
	// Chrome must honor excludeCredentials: an authenticator that holds
	// one of the excluded credentials refuses to create another.
	a.expectCreateRefused("a registration excluding the authenticator's credential",
		"InvalidStateError", []string{a.record})
	a.close()

	// Backup flags: a synced credential, and one that gets synced after
	// its registration, and unsynced again.
	opts := platformAuthenticator()
	opts.DefaultBackupEligibility = true
	opts.DefaultBackupState = true
	a = s.addAuthenticator("synced",
		"A CTAP2.1 platform authenticator whose credentials are "+
			"backup eligible and backed up.", opts)
	a.register()
	a.login()
	a.close()

	opts = platformAuthenticator()
	opts.DefaultBackupEligibility = true
	a = s.addAuthenticator("backup-eligible",
		"A CTAP2.1 platform authenticator whose credentials are "+
			"backup eligible but not backed up; the credential is "+
			"backed up between the first and the second login, and "+
			"not backed up again before the third.", opts)
	a.register()
	a.login()
	a.setBackupFlags(true, true)
	a.login()
	a.setBackupFlags(true, false)
	a.login()
	a.close()

	// Roaming authenticators. Chrome zeroes the AAGUID of the USB one,
	// but not of the hybrid one.
	opts = platformAuthenticator()
	opts.Transport = webauthn.AuthenticatorTransportUsb
	a = s.addAuthenticator("security-key",
		"A CTAP2.1 USB authenticator with user verification.", opts)
	a.register()
	a.login()
	a.close()

	opts = platformAuthenticator()
	opts.Transport = webauthn.AuthenticatorTransportHybrid
	opts.DefaultBackupEligibility = true
	opts.DefaultBackupState = true
	a = s.addAuthenticator("hybrid",
		"A CTAP2.1 authenticator reached over the hybrid transport "+
			"(a phone), with user verification, whose credentials are "+
			"backup eligible and backed up.", opts)
	a.register()
	a.login()
	a.close()

	// A platform authenticator that can't verify the user: Chrome
	// creates the discoverable credential anyway, as registration
	// requests user verification "preferred" (it refuses to on a
	// security key, see below), but honors "required" at login by
	// refusing to assert it.
	opts = platformAuthenticator()
	opts.HasUserVerification = false
	opts.IsUserVerified = false
	a = s.addAuthenticator("no-user-verification",
		"A CTAP2.1 platform authenticator without user verification: "+
			"Chrome creates the credential, but refuses to assert it "+
			"with user verification required, so there are no logins.", opts)
	a.register()
	a.expectGetRefused("a login on an authenticator without user verification", "NotAllowedError")
	a.close()

	// Responses altered by the response override bits of the DevTools
	// protocol, which clear the user verification or user presence flag,
	// or zero the signature. Chrome applies them after its own checks,
	// so the responses reach the page even though the options request
	// user verification, and the replay checks that the package refuses
	// them.
	a = s.addAuthenticator("uv-cleared-after-registration",
		"A CTAP2.1 platform authenticator that verifies the user at "+
			"registration, then clears the user verification flag in its "+
			"assertions: a client not honoring the user verification "+
			"requirement.", platformAuthenticator())
	a.register()
	a.setOverrides(overrides{badUV: true})
	a.login()
	a.close()

	a = s.addAuthenticator("uv-set-up-after-registration",
		"A CTAP2.1 platform authenticator that clears the user "+
			"verification flag at registration, then verifies the user in "+
			"its assertions: a security key whose PIN was set up after "+
			"registration, possibly by whoever took it.", platformAuthenticator())
	a.setOverrides(overrides{badUV: true})
	a.register()
	a.setOverrides(overrides{})
	a.login()
	a.close()

	a = s.addAuthenticator("no-user-presence",
		"A CTAP2.1 platform authenticator that clears the user presence "+
			"flag in every response.", platformAuthenticator())
	a.setOverrides(overrides{badUP: true})
	a.register()
	a.login()
	a.close()

	a = s.addAuthenticator("bogus-signature",
		"A CTAP2.1 platform authenticator whose assertion signatures "+
			"are zeroed.", platformAuthenticator())
	a.setOverrides(overrides{bogusSignature: true})
	a.register()
	a.login()
	a.close()

	// A credential that claims to be backed up without being backup
	// eligible, which the flags' definition rules out.
	a = s.addAuthenticator("backed-up-not-eligible",
		"A CTAP2.1 platform authenticator whose credential is marked "+
			"backed up but not backup eligible after registration.",
		platformAuthenticator())
	a.register()
	a.setBackupFlags(false, true)
	a.login()
	a.close()

	// Chrome must honor residentKey: "required", which a U2F
	// authenticator can't satisfy, and it won't store a discoverable
	// credential on a security key that can't verify the user (one
	// without a PIN), as its PIN would protect the credential.
	a = s.addAuthenticator("u2f", "", &webauthn.VirtualAuthenticatorOptions{
		Protocol:                    webauthn.AuthenticatorProtocolU2f,
		Transport:                   webauthn.AuthenticatorTransportUsb,
		AutomaticPresenceSimulation: true,
	})
	a.expectCreateRefused("a U2F registration", "NotAllowedError", nil)
	a.discard()

	opts = platformAuthenticator()
	opts.Transport = webauthn.AuthenticatorTransportUsb
	opts.HasUserVerification = false
	opts.IsUserVerified = false
	a = s.addAuthenticator("security-key-without-pin", "", opts)
	a.expectCreateRefused("a registration on a security key without user verification",
		"NotAllowedError", nil)
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

	rp, err := passkey.NewRelyingParty("localhost", origin, passkey.Options{})
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
	// The browser is started on this context, so the timeout bounds the
	// whole run.
	ctx, cancelTimeout := context.WithTimeout(ctx, 2*time.Minute)
	cancel := func() {
		cancelTimeout()
		cancelBrowser()
		cancelAllocator()
	}

	// Start the browser, and read its version.
	version, err := chromedp.CallBrowser(ctx, browser.GetVersion, cdp.Empty{})
	if err != nil {
		cancel()
		log.Fatal(err)
	}
	log.Printf("recording with %s at %s", version.Product, origin)

	s := &session{
		rp:     rp,
		user:   passkey.User{ID: rand.Text(), Name: "user@example.com"},
		url:    origin + "/",
		server: server,
		ctx:    ctx,
		cancel: cancel,
	}
	s.out.Browser = version.Product
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

// overrides are the response override bits of the DevTools protocol:
// each one breaks the responses of an authenticator in one way.
type overrides struct {
	badUV, badUP, bogusSignature bool
}

// authenticator is a virtual authenticator in a tab of its own, and the
// recording of the ceremonies it performs.
type authenticator struct {
	s      *session
	ctx    context.Context // the tab
	cancel context.CancelFunc
	id     webauthn.AuthenticatorID
	opts   *webauthn.VirtualAuthenticatorOptions
	// overrides are the response override bits in effect.
	overrides overrides

	rec *recording
	// record is the passkey record of the registered credential (empty
	// if Register refused it), credentialID its credential ID, and
	// backupEligible and backedUp its current backup flags.
	record         string
	credentialID   []byte
	backupEligible bool
	backedUp       bool
}

// addAuthenticator opens a tab on the page and adds a virtual
// authenticator to it, with the given options. The tab is scoped to the
// authenticator, so that a login ceremony sees exactly one
// authenticator: it is closed by close or discard.
func (s *session) addAuthenticator(name, description string, opts *webauthn.VirtualAuthenticatorOptions) *authenticator {
	ctx, cancel := chromedp.NewContext(s.ctx)
	a := &authenticator{
		s:              s,
		ctx:            ctx,
		cancel:         cancel,
		opts:           opts,
		backupEligible: opts.DefaultBackupEligibility,
		backedUp:       opts.DefaultBackupState,
		rec: &recording{
			Name:           name,
			Description:    description,
			BackupEligible: opts.DefaultBackupEligibility,
			BackedUp:       opts.DefaultBackupState,
		},
	}
	if err := chromedp.Do(ctx, chromedp.Navigate(s.url)); err != nil {
		s.fatalf("%s: %v", name, err)
	}
	// WebAuthn ceremonies require the document to be focused, which a
	// background tab is not.
	if _, err := chromedp.Call(ctx, page.BringToFront, cdp.Empty{}); err != nil {
		s.fatalf("%s: focusing the tab: %v", name, err)
	}
	if _, err := chromedp.Call(ctx, webauthn.Enable, webauthn.EnableParams{}); err != nil {
		s.fatalf("%s: enabling the WebAuthn domain: %v", name, err)
	}
	res, err := chromedp.Call(ctx, webauthn.AddVirtualAuthenticator,
		webauthn.AddVirtualAuthenticatorParams{Options: opts})
	if err != nil {
		s.fatalf("%s: adding a virtual authenticator: %v", name, err)
	}
	a.id = res.AuthenticatorID
	return a
}

// close closes the tab and keeps the recording.
func (a *authenticator) close() {
	if a.rec.Logins == nil {
		a.rec.Logins = []login{}
	}
	a.s.out.Recordings = append(a.s.out.Recordings, *a.rec)
	a.cancel()
}

// discard closes the tab and drops the recording.
func (a *authenticator) discard() {
	a.cancel()
}

// setOverrides sets the response override bits of the authenticator,
// replacing those in effect.
func (a *authenticator) setOverrides(o overrides) {
	ptr := func(b bool) *bool { return &b }
	_, err := chromedp.Call(a.ctx, webauthn.SetResponseOverrideBits, webauthn.SetResponseOverrideBitsParams{
		AuthenticatorID:  a.id,
		IsBadUV:          ptr(o.badUV),
		IsBadUP:          ptr(o.badUP),
		IsBogusSignature: ptr(o.bogusSignature),
	})
	if err != nil {
		a.s.fatalf("%s: setting the response overrides: %v", a.rec.Name, err)
	}
	a.overrides = o
}

// verifiesUser reports whether the authenticator's responses carry the
// user verification flag.
func (a *authenticator) verifiesUser() bool {
	return a.opts.HasUserVerification && a.opts.IsUserVerified && !a.overrides.badUV
}

// eval evaluates an async JavaScript expression in the tab and returns
// its result. If the expression throws, the error is the exception.
func (a *authenticator) eval(js string) (string, error) {
	return chromedp.Run(a.ctx, chromedp.Evaluate[string](js, chromedp.EvalAwaitPromise))
}

// exceptionName returns the name of a JavaScript exception. Protocol and
// context errors return an empty name.
func exceptionName(err error) string {
	var e *chromedp.ExceptionError
	if !errors.As(err, &e) || e.Exception == nil {
		return ""
	}
	name, _, _ := strings.Cut(e.Exception.Description, ":")
	return name
}

// create runs a registration ceremony in the tab, excluding the given
// passkeys, and returns the creation options along with the serialized
// response, exactly as PublicKeyCredential.toJSON() produced it.
func (a *authenticator) create(passkeys []string) (optionsJSON, responseJSON []byte, err error) {
	optionsJSON, err = a.s.rp.NewRegistration(a.s.user, passkey.RegistrationOptions{ExcludeCredentials: passkeys})
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

// expectCreateRefused runs a registration ceremony that the client must
// refuse with the named exception, and logs the refusal.
func (a *authenticator) expectCreateRefused(what, wantName string, passkeys []string) {
	_, _, err := a.create(passkeys)
	if err == nil {
		a.s.fatalf("%s succeeded, want %s", what, wantName)
	}
	if got := exceptionName(err); got != wantName {
		a.s.fatalf("%s failed with %v, want %s", what, err, wantName)
	}
	log.Printf("%s refused by the client, as expected: %v", what, err)
}

// expectGetRefused runs a login ceremony that the client must refuse
// with the named exception, and logs the refusal.
func (a *authenticator) expectGetRefused(what, wantName string) {
	_, optionsJSON, err := a.s.rp.NewLogin(passkey.LoginOptions{})
	if err != nil {
		a.s.fatalf("%v", err)
	}
	_, err = a.get(optionsJSON)
	if err == nil {
		a.s.fatalf("%s succeeded, want %s", what, wantName)
	}
	if got := exceptionName(err); got != wantName {
		a.s.fatalf("%s failed with %v, want %s", what, err, wantName)
	}
	log.Printf("%s refused by the client, as expected: %v", what, err)
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
	a.rec.UserVerified = a.verifiesUser()
	// The record is needed to build excludeCredentials and
	// allowCredentials, so Register has to succeed here as well as at
	// replay time. The exception is a response without the UV flag,
	// which Register refuses: the replay builds its record as an
	// importer would, and checks that its logins are refused too.
	a.record, err = a.s.rp.Register(responseJSON)
	if err != nil && !(!a.verifiesUser() && errors.Is(err, passkey.ErrUserVerificationUnavailable)) {
		a.s.fatalf("%s: Register: %v\n%s", a.rec.Name, err, responseJSON)
	}

	var resp struct {
		RawID    string `json:"rawId"`
		Response struct {
			AuthenticatorData string   `json:"authenticatorData"`
			Transports        []string `json:"transports"`
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
	// Chrome may report more transports than the one configured: a
	// hybrid authenticator also advertises BLE.
	a.rec.Transports = slices.Compact(slices.Sorted(slices.Values(resp.Response.Transports)))
	a.rec.Registration.Options = optionsJSON
	a.rec.Registration.Response = responseJSON
	if a.record == "" {
		log.Printf("%s: registration refused, as expected: %v", a.rec.Name, err)
	} else {
		log.Printf("%s: registered %s", a.rec.Name, a.record)
	}
}

// login runs a login ceremony and records the exchange.
func (a *authenticator) login() {
	request, optionsJSON, err := a.s.rp.NewLogin(passkey.LoginOptions{})
	if err != nil {
		a.s.fatalf("%v", err)
	}
	a.recordLogin(request, optionsJSON, false)
}

// loginWithCredentials runs a user-scoped login ceremony and records the
// exchange.
func (a *authenticator) loginWithCredentials() {
	request, optionsJSON, err := a.s.rp.NewLogin(passkey.LoginOptions{AllowCredentials: []string{a.record}})
	if err != nil {
		a.s.fatalf("%v", err)
	}
	a.recordLogin(request, optionsJSON, true)
}

func (a *authenticator) recordLogin(request, optionsJSON []byte, userScoped bool) {
	responseJSON, err := a.get(optionsJSON)
	if err != nil {
		a.s.fatalf("%s: login: %v", a.rec.Name, err)
	}
	l := login{
		Request:      hex.EncodeToString(request),
		Options:      optionsJSON,
		Response:     responseJSON,
		UserScoped:   userScoped,
		UserVerified: a.verifiesUser(),
		BackedUp:     a.backedUp,
	}
	switch {
	case a.overrides.badUP:
		l.Error = errorUserPresence
	case a.overrides.bogusSignature:
		l.Error = errorSignature
	case a.backedUp && !a.backupEligible:
		l.Error = errorBackupState
	}
	a.rec.Logins = append(a.rec.Logins, l)
	log.Printf("%s: login %d recorded", a.rec.Name, len(a.rec.Logins))
}

// setBackupFlags changes the backup eligibility and state the credential
// reports.
func (a *authenticator) setBackupFlags(eligible, backedUp bool) {
	_, err := chromedp.Call(a.ctx, webauthn.SetCredentialProperties, webauthn.SetCredentialPropertiesParams{
		AuthenticatorID:   a.id,
		CredentialID:      a.credentialID,
		BackupEligibility: &eligible,
		BackupState:       &backedUp,
	})
	if err != nil {
		a.s.fatalf("%s: setting the backup flags: %v", a.rec.Name, err)
	}
	a.backupEligible = eligible
	a.backedUp = backedUp
}

// setSignCount sets the credential's signature counter.
func (a *authenticator) setSignCount(n float64) {
	_, err := chromedp.Call(a.ctx, webauthn.SetCredentialProperties, webauthn.SetCredentialPropertiesParams{
		AuthenticatorID: a.id,
		CredentialID:    a.credentialID,
		SignCount:       &n,
	})
	if err != nil {
		a.s.fatalf("%s: setting the signature counter: %v", a.rec.Name, err)
	}
}

// decode decodes a base64url field of the WebAuthn JSON serialization.
func (a *authenticator) decode(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		a.s.fatalf("%v", err)
	}
	return b
}
