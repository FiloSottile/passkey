// Command capture serves a site that records real WebAuthn ceremonies —
// performed by whoever visits it, with whatever client and authenticator
// they have — as they pass through filippo.io/passkey, so that the exact
// shapes real clients produce can be replayed by the package tests.
//
// It is a separate module with a replace directive for filippo.io/passkey,
// so it compiles against the working tree and needs nothing beyond the
// standard library and the package. Run it locally with
//
//	go run -C testdata/_capture .
//
// and deploy it as a single binary with -listen, -origin, and -data set.
//
// # Sessions and recordings
//
// A visitor describes their authenticator, then walks through a script of
// ceremonies: a registration and a few logins, under both of the
// package's user verification policies (see [passkey.Options]), so that
// real "preferred" vs "required" divergences show. Every ceremony is
// verified by the package under both policies, and the whole exchange —
// the options the package emitted, the response exactly as
// PublicKeyCredential.toJSON() produced it, or the client's refusal —
// is appended to the session's recording, which is written to the data
// directory after every step, so nothing is lost if the visitor stops
// early. A separate, linked session captures a conditional (automatic)
// registration, which needs a password sign-in first.
//
// Each session is one file, <time>-<random>.json, in the format of the
// recording type below: one authenticator, one contributor, an ordered
// list of ceremonies. Registrations produce passkey records; logins are
// verified against the records the session has produced so far. The
// format is meant to stand alone, so that other relying party
// implementations can replay it: the challenge is in each login's
// options, and the properties a consumer would check are spelled out
// next to the raw exchange.
package main

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"filippo.io/passkey"
)

//go:embed index.html
var indexHTML []byte

// recording is a session's file: one authenticator, one contributor, and
// the ceremonies they performed, in order.
type recording struct {
	// ID is the session ID, which is also the file name.
	ID   string    `json:"id"`
	Time time.Time `json:"time"`
	// License is the terms the contributor submitted the recording under.
	License string `json:"license"`

	RPID   string `json:"rpId"`
	Origin string `json:"origin"`

	Client        client `json:"client"`
	Authenticator string `json:"authenticator"`
	Contributor   string `json:"contributor,omitempty"`
	Notes         string `json:"notes,omitempty"`

	// UserID and UserName are the user the credentials were registered
	// for; a session is one user, so that excludeCredentials and
	// same-user re-registration behave as they would in production.
	UserID   string `json:"userId"`
	UserName string `json:"userName"`

	// Previous is the session this one continues, for a conditional
	// registration made after a regular session.
	Previous string `json:"previous,omitempty"`

	Ceremonies []*ceremony `json:"ceremonies"`
}

// client describes the browser, as it described itself.
type client struct {
	UserAgent string `json:"userAgent"`
	// Capabilities is what PublicKeyCredential.getClientCapabilities()
	// returned, if it exists.
	Capabilities json.RawMessage `json:"capabilities,omitempty"`
	// Unsupported names the WebAuthn JSON API the client lacked, if it
	// could not run the ceremonies at all.
	Unsupported string `json:"unsupported,omitempty"`
}

// ceremony is one registration or login: what was asked, what came back,
// what the contributor observed, and what the package made of it.
type ceremony struct {
	Type string    `json:"type"` // registration or login
	Time time.Time `json:"time"`
	// Conditional reports a ceremony run with mediation: "conditional":
	// an automatic registration after a password sign-in, or an
	// autofill login.
	Conditional bool `json:"conditional,omitempty"`
	// UserVerification is what the options requested: always "preferred"
	// for registrations; "required" or "preferred" for logins, by
	// which policy produced them.
	UserVerification string `json:"userVerification"`
	// UserScoped reports a login begun with NewLoginWithCredentials.
	UserScoped bool `json:"userScoped,omitempty"`

	// Options is what the package emitted, and Response what
	// PublicKeyCredential.toJSON() produced — or ClientError why the
	// client produced nothing.
	Options     json.RawMessage `json:"options"`
	Response    json.RawMessage `json:"response,omitempty"`
	ClientError *clientError    `json:"clientError,omitempty"`

	// Prompt is what the client asked of the contributor, in their words.
	Prompt string `json:"prompt,omitempty"`

	// Properties are read out of the response, for a consumer to check.
	Properties *properties `json:"properties,omitempty"`
	// Record is the passkey record a registration produced.
	Record string `json:"record,omitempty"`
	// Outcomes are the package's verdicts, under both policies.
	Outcomes *outcomes `json:"outcomes,omitempty"`
}

type clientError struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

// properties are the values a relying party would read out of a
// response, spelled out.
type properties struct {
	// AuthenticatorAttachment is the credential's, as reported.
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	CredentialID            string `json:"credentialId"` // hex
	// Algorithm is the COSE algorithm of the credential public key
	// (registrations), and PublicKeyAlgorithm what the client reported
	// alongside it, if it did.
	Algorithm          *int64          `json:"algorithm,omitempty"`
	PublicKeyAlgorithm *int64          `json:"publicKeyAlgorithm,omitempty"`
	AAGUID             string          `json:"aaguid,omitempty"` // hex, registrations
	Transports         []string        `json:"transports,omitempty"`
	CredProps          json.RawMessage `json:"credProps,omitempty"`
	// UserHandle is the login response's, if the member was present:
	// its base64url decoding, so "" is a present-but-empty handle.
	UserHandle *string `json:"userHandle,omitempty"`

	// The authenticator data flags and counter.
	UserPresent    bool   `json:"userPresent"`
	UserVerified   bool   `json:"userVerified"`
	BackupEligible bool   `json:"backupEligible"`
	BackedUp       bool   `json:"backedUp"`
	ExtensionData  bool   `json:"extensionData"`
	SignCount      uint32 `json:"signCount"`

	// ClientData is the decoded clientDataJSON.
	ClientData json.RawMessage `json:"clientData"`
}

// outcomes are the package's verdicts on a ceremony, under its default
// policy and with OptionalUserVerification set.
type outcomes struct {
	Default                  outcome `json:"default"`
	OptionalUserVerification outcome `json:"optionalUserVerification"`
}

type outcome struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Sentinel names the sentinel error, if the error was one.
	Sentinel string `json:"sentinel,omitempty"`
	// Result is a successful login's.
	Result *loginResult `json:"result,omitempty"`
}

type loginResult struct {
	Matched      int  `json:"matched"`
	UserVerified bool `json:"userVerified"`
	BackedUp     bool `json:"backedUp"`
}

// The recording license.
const license = "CC0-1.0"

func main() {
	log.SetFlags(0)
	listen := flag.String("listen", "", "address to listen on (default localhost:8080, or :$PORT if set)")
	origin := flag.String("origin", "http://localhost:8080", "the origin the site is served at")
	rpID := flag.String("rpid", "", "the RP ID (default: the origin's host)")
	data := flag.String("data", "recordings", "directory to write recordings to")
	token := flag.String("token", "", "if set, a token visitors must present as ?t=")
	flag.Parse()

	if *listen == "" {
		*listen = "localhost:8080"
		if port := os.Getenv("PORT"); port != "" {
			*listen = ":" + port
		}
	}
	if *rpID == "" {
		u, err := url.Parse(*origin)
		if err != nil || u.Hostname() == "" {
			log.Fatalf("can't derive the RP ID from origin %q; set -rpid", *origin)
		}
		*rpID = u.Hostname()
	}
	if err := os.MkdirAll(*data, 0o755); err != nil {
		log.Fatal(err)
	}

	s, err := newServer(*rpID, *origin, *data, *token)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("serving %s (RP ID %s) on %s, recording to %s", *origin, *rpID, *listen, *data)
	log.Fatal(http.ListenAndServe(*listen, s.handler()))
}

// server is the site: two relying parties, one per user verification
// policy, and the live sessions.
type server struct {
	rpID, origin string
	// strict is the package's default policy; lax has
	// OptionalUserVerification set. Options that are the same under both
	// come from lax, so that a device that skips user verification is
	// recorded rather than refused; every response is verified under both.
	strict, lax *passkey.RelyingParty
	data        string
	token       string

	mu       sync.Mutex
	sessions map[string]*session
}

func newServer(rpID, origin, data, token string) (*server, error) {
	strict, err := passkey.NewRelyingParty(&passkey.Options{RPID: rpID, Origin: origin})
	if err != nil {
		return nil, err
	}
	lax, err := passkey.NewRelyingParty(&passkey.Options{RPID: rpID, Origin: origin, OptionalUserVerification: true})
	if err != nil {
		return nil, err
	}
	return &server{
		rpID: rpID, origin: origin,
		strict: strict, lax: lax,
		data: data, token: token,
		sessions: make(map[string]*session),
	}, nil
}

// session is a recording in progress, and the state its ceremonies need
// between the options and the response.
type session struct {
	mu   sync.Mutex
	rec  *recording
	path string
	// password is the one the visitor saved in their password manager
	// for a conditional registration, whatever they submitted; it lives
	// only in memory.
	password string
	// conditionalSignIn reports that the visitor completed the password
	// sign-in which makes a conditional registration meaningful. It remains
	// set across refused attempts so the visitor can retry.
	conditionalSignIn bool
	// records are the passkey records the session's registrations
	// produced so far, in order.
	records []string
	// pending are the login requests whose options are out, by request
	// ID, and pendingRegistration the registration options that are out.
	pending             map[string]*pendingLogin
	pendingRegistration *pendingRegistration
}

type pendingLogin struct {
	request     []byte
	options     json.RawMessage
	rp          *passkey.RelyingParty
	uv          string
	scoped      bool
	conditional bool
}

type pendingRegistration struct {
	options     json.RawMessage
	conditional bool
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	mux.HandleFunc("POST /api/session", s.newSession)
	mux.HandleFunc("GET /api/session/{id}", s.getSession)
	mux.HandleFunc("POST /api/session/{id}/annotate", s.annotate)
	mux.HandleFunc("POST /api/session/{id}/registration/options", s.registrationOptions)
	mux.HandleFunc("POST /api/session/{id}/registration", s.registration)
	mux.HandleFunc("POST /api/session/{id}/login/options", s.loginOptions)
	mux.HandleFunc("POST /api/session/{id}/login", s.login)
	mux.HandleFunc("POST /password", s.password)

	// The registration endpoint adds a passkey to a session; the visitor
	// is the only one who should, so cross-site requests are refused as
	// they would be in the application this site stands in for.
	var h http.Handler = http.NewCrossOriginProtection().Handler(mux)
	if s.token != "" {
		h = s.requireToken(h)
	}
	return h
}

// requireToken gates every request on the token, which the page carries
// in its URL and forwards on API calls.
func (s *server) requireToken(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := r.URL.Query().Get("t")
		if t == "" {
			t = r.Header.Get("X-Capture-Token")
		}
		if t == "" {
			t = r.PostFormValue("t")
		}
		if subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) != 1 {
			http.Error(w, "this site is invitation-only: the link you were given carries a token", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// newSession starts a session from the visitor's description of their
// setup, and writes its first, empty recording.
func (s *server) newSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Authenticator string          `json:"authenticator"`
		Contributor   string          `json:"contributor"`
		Notes         string          `json:"notes"`
		Capabilities  json.RawMessage `json:"capabilities"`
		Unsupported   string          `json:"unsupported"`
		Previous      string          `json:"previous"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Authenticator = strings.TrimSpace(req.Authenticator)
	if req.Authenticator == "" {
		http.Error(w, "describe the authenticator", http.StatusBadRequest)
		return
	}
	for _, f := range []*string{&req.Authenticator, &req.Contributor, &req.Notes, &req.Previous} {
		*f = clip(*f, 500)
	}
	if !json.Valid(req.Capabilities) {
		req.Capabilities = nil
	}

	now := time.Now().UTC()
	id := now.Format("20060102T150405Z") + "-" + rand.Text()
	sess := &session{
		rec: &recording{
			ID:      id,
			Time:    now,
			License: license,
			RPID:    s.rpID,
			Origin:  s.origin,
			Client: client{
				UserAgent:    clip(r.UserAgent(), 500),
				Capabilities: req.Capabilities,
				Unsupported:  clip(req.Unsupported, 200),
			},
			Authenticator: req.Authenticator,
			Contributor:   req.Contributor,
			Notes:         req.Notes,
			UserID:        rand.Text(),
			UserName:      id,
			Previous:      req.Previous,
			Ceremonies:    []*ceremony{},
		},
		path:    filepath.Join(s.data, id+".json"),
		pending: make(map[string]*pendingLogin),
	}
	if err := sess.save(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	// Sessions live in memory for a day; their files stay.
	for id, old := range s.sessions {
		if time.Since(old.rec.Time) > 24*time.Hour {
			delete(s.sessions, id)
		}
	}
	s.sessions[id] = sess
	s.mu.Unlock()
	log.Printf("%s: new session: %s (%s)", id, req.Authenticator, sess.rec.Client.UserAgent)
	writeJSON(w, sess.view())
}

// session looks a session up, answering the request if it isn't there.
func (s *server) session(w http.ResponseWriter, r *http.Request) *session {
	s.mu.Lock()
	sess := s.sessions[r.PathValue("id")]
	s.mu.Unlock()
	if sess == nil {
		http.Error(w, "unknown or expired session: start again", http.StatusNotFound)
	}
	return sess
}

func (s *server) getSession(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r)
	if sess == nil {
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	writeJSON(w, sess.view())
}

// view is what the page sees of a session: the recording.
func (sess *session) view() any {
	return sess.rec
}

// annotate records the contributor's notes: on the session, or on a
// ceremony (what the client asked of them).
func (s *server) annotate(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r)
	if sess == nil {
		return
	}
	var req struct {
		Ceremony *int   `json:"ceremony"`
		Text     string `json:"text"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Text = clip(strings.TrimSpace(req.Text), 1000)
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if req.Ceremony == nil {
		sess.rec.Notes = req.Text
	} else if i := *req.Ceremony; i >= 0 && i < len(sess.rec.Ceremonies) {
		sess.rec.Ceremonies[i].Prompt = req.Text
	} else {
		http.Error(w, "no such ceremony", http.StatusBadRequest)
		return
	}
	if err := sess.save(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, sess.view())
}

// registrationOptions begins a registration. The options are the same
// under both policies, so they come from lax; excludeCredentials carries
// the session's records, as an application's would.
func (s *server) registrationOptions(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r)
	if sess == nil {
		return
	}
	var req struct {
		Conditional bool `json:"conditional"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if req.Conditional && !sess.conditionalSignIn {
		http.Error(w, "complete the password sign-in before conditional registration", http.StatusForbidden)
		return
	}
	user := passkey.User{ID: sess.rec.UserID, Name: sess.rec.UserName}
	options, err := s.lax.NewRegistration(user, sess.records)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sess.pendingRegistration = &pendingRegistration{options: options, conditional: req.Conditional}
	writeJSON(w, map[string]any{"options": json.RawMessage(options)})
}

// registration completes a registration: the response, or the client's
// refusal, is verified under both policies and appended to the
// recording.
func (s *server) registration(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r)
	if sess == nil {
		return
	}
	var req struct {
		Response    json.RawMessage `json:"response"`
		ClientError *clientError    `json:"clientError"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	p := sess.pendingRegistration
	if p == nil {
		http.Error(w, "no registration in progress", http.StatusBadRequest)
		return
	}
	sess.pendingRegistration = nil

	c := &ceremony{
		Type:             "registration",
		Time:             time.Now().UTC(),
		Conditional:      p.conditional,
		UserVerification: "preferred",
		Options:          p.options,
	}
	if req.ClientError != nil || len(req.Response) == 0 {
		c.ClientError = clipError(req.ClientError)
	} else {
		c.Response = req.Response
		c.Properties = registrationProperties(req.Response)
		c.Outcomes = &outcomes{}
		record, err := s.lax.Register(req.Response)
		c.Outcomes.OptionalUserVerification = registrationOutcome(err)
		if err == nil {
			c.Record = record
			sess.records = append(sess.records, record)
			if p.conditional {
				sess.conditionalSignIn = false
			}
		}
		_, err = s.strict.Register(req.Response)
		c.Outcomes.Default = registrationOutcome(err)
	}
	sess.rec.Ceremonies = append(sess.rec.Ceremonies, c)
	if err := sess.save(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("%s: %s", sess.rec.ID, c.summary())
	writeJSON(w, map[string]any{"index": len(sess.rec.Ceremonies) - 1, "ceremony": c})
}

// loginOptions begins a login under the requested policy, unscoped or
// with the session's records as allowCredentials.
func (s *server) loginOptions(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r)
	if sess == nil {
		return
	}
	var req struct {
		UserVerification string `json:"userVerification"`
		UserScoped       bool   `json:"userScoped"`
		Conditional      bool   `json:"conditional"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	var rp *passkey.RelyingParty
	switch req.UserVerification {
	case "required":
		rp = s.strict
	case "preferred":
		rp = s.lax
	default:
		http.Error(w, `userVerification must be "required" or "preferred"`, http.StatusBadRequest)
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	var request, options []byte
	var err error
	if req.UserScoped {
		if len(sess.records) == 0 {
			http.Error(w, "register a passkey first", http.StatusBadRequest)
			return
		}
		request, options, err = rp.NewLoginWithCredentials(sess.records)
	} else {
		request, options, err = rp.NewLogin()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := passkey.RequestID(request)
	sess.pending[id] = &pendingLogin{
		request: request, options: options, rp: rp,
		uv: req.UserVerification, scoped: req.UserScoped, conditional: req.Conditional,
	}
	writeJSON(w, map[string]any{"requestId": id, "options": json.RawMessage(options)})
}

// login completes a login: the response, or the client's refusal, is
// verified under both policies against the session's records and
// appended to the recording. Requests are single-use.
func (s *server) login(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r)
	if sess == nil {
		return
	}
	var req struct {
		RequestID   string          `json:"requestId"`
		Response    json.RawMessage `json:"response"`
		ClientError *clientError    `json:"clientError"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	p := sess.pending[req.RequestID]
	if p == nil {
		http.Error(w, "unknown or already used login request", http.StatusBadRequest)
		return
	}
	delete(sess.pending, req.RequestID)

	c := &ceremony{
		Type:             "login",
		Time:             time.Now().UTC(),
		Conditional:      p.conditional,
		UserVerification: p.uv,
		UserScoped:       p.scoped,
		Options:          p.options,
	}
	if req.ClientError != nil || len(req.Response) == 0 {
		c.ClientError = clipError(req.ClientError)
	} else {
		c.Response = req.Response
		c.Properties = loginProperties(req.Response)
		c.Outcomes = &outcomes{}
		response, err := passkey.ParseResponse(req.Response)
		if err != nil {
			c.Outcomes.Default = outcome{Error: err.Error()}
			c.Outcomes.OptionalUserVerification = c.Outcomes.Default
		} else if response.RequestID() != req.RequestID {
			c.Outcomes.Default = outcome{Error: "response is for a different request"}
			c.Outcomes.OptionalUserVerification = c.Outcomes.Default
		} else {
			// The options were produced by one policy; the other's
			// verdict says what it would have made of the assertion.
			result, err := s.strict.Login(response, p.request, sess.records)
			c.Outcomes.Default = loginOutcome(result, err)
			result, err = s.lax.Login(response, p.request, sess.records)
			c.Outcomes.OptionalUserVerification = loginOutcome(result, err)
		}
	}
	sess.rec.Ceremonies = append(sess.rec.Ceremonies, c)
	if err := sess.save(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("%s: %s", sess.rec.ID, c.summary())
	writeJSON(w, map[string]any{"index": len(sess.rec.Ceremonies) - 1, "ceremony": c})
}

// summary is a log line for a ceremony.
func (c *ceremony) summary() string {
	kind := c.Type + " (" + c.UserVerification
	if c.UserScoped {
		kind += ", user-scoped"
	}
	if c.Conditional {
		kind += ", conditional"
	}
	kind += ")"
	if c.ClientError != nil {
		return kind + ": client refused: " + c.ClientError.Name + ": " + c.ClientError.Message
	}
	verdict := func(o outcome) string {
		if o.OK {
			return "ok"
		}
		if o.Sentinel != "" {
			return o.Sentinel
		}
		return "error"
	}
	return kind + ": default " + verdict(c.Outcomes.Default) +
		", optional UV " + verdict(c.Outcomes.OptionalUserVerification)
}

// password is the sign-in form of the conditional registration flow: a
// real form submission, so that the password manager offers to save the
// password, and later autofills it. The save step keeps whatever
// password was submitted — the visitor's, or one the manager generated,
// since managers only offer to save what was typed or filled — and the
// sign-in step checks it. Only the password is checked: some managers
// fill the username of the login item they hold for the site, which may
// be an earlier session's. It redirects back to the page, which then
// asks for a conditional registration.
func (s *server) password(w http.ResponseWriter, r *http.Request) {
	id := r.PostFormValue("session")
	s.mu.Lock()
	sess := s.sessions[id]
	s.mu.Unlock()
	if sess == nil {
		http.Error(w, "unknown or expired session: start again", http.StatusNotFound)
		return
	}
	// The page reads the outcome from the pw parameter: saved, signedin,
	// or wrong.
	var outcome string
	password := r.PostFormValue("password")
	sess.mu.Lock()
	switch r.PostFormValue("step") {
	case "save":
		outcome = "saved"
		if password == "" {
			outcome = "wrong"
		} else {
			sess.password = clip(password, 200)
		}
	case "signin":
		outcome = "signedin"
		if sess.password == "" || subtle.ConstantTimeCompare([]byte(password), []byte(sess.password)) != 1 {
			outcome = "wrong"
		} else {
			sess.conditionalSignIn = true
		}
	default:
		sess.mu.Unlock()
		http.Error(w, "bad step", http.StatusBadRequest)
		return
	}
	sess.mu.Unlock()
	q := url.Values{"s": {id}, "pw": {outcome}}
	if s.token != "" {
		q.Set("t", s.token)
	}
	http.Redirect(w, r, "/?"+q.Encode(), http.StatusSeeOther)
}

// save writes the recording to its file, atomically.
func (sess *session) save() error {
	b, err := json.MarshalIndent(sess.rec, "", "\t")
	if err != nil {
		return err
	}
	tmp := sess.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, sess.path)
}

// registrationOutcome classifies a Register error.
func registrationOutcome(err error) outcome {
	if err == nil {
		return outcome{OK: true}
	}
	return outcome{Error: err.Error(), Sentinel: sentinel(err)}
}

// loginOutcome classifies a Login result.
func loginOutcome(result *passkey.LoginResult, err error) outcome {
	if err != nil {
		return outcome{Error: err.Error(), Sentinel: sentinel(err)}
	}
	return outcome{OK: true, Result: &loginResult{
		Matched:      result.Matched,
		UserVerified: result.UserVerified,
		BackedUp:     result.BackedUp,
	}}
}

func sentinel(err error) string {
	switch {
	case errors.Is(err, passkey.ErrUserVerificationUnavailable):
		return "user-verification-unavailable"
	case errors.Is(err, passkey.ErrUnknownCredential):
		return "unknown-credential"
	case errors.Is(err, passkey.ErrRequestExpired):
		return "request-expired"
	case errors.Is(err, passkey.ErrUnsupportedAlgorithm):
		return "unsupported-algorithm"
	}
	return ""
}

// registrationProperties reads a registration response, tolerating any
// shape: it describes what the client sent, whatever the package makes
// of it.
func registrationProperties(responseJSON []byte) *properties {
	var r struct {
		RawID                   string `json:"rawId"`
		AuthenticatorAttachment string `json:"authenticatorAttachment"`
		Response                struct {
			ClientDataJSON     string   `json:"clientDataJSON"`
			AuthenticatorData  string   `json:"authenticatorData"`
			AttestationObject  string   `json:"attestationObject"`
			Transports         []string `json:"transports"`
			PublicKeyAlgorithm *int64   `json:"publicKeyAlgorithm"`
		} `json:"response"`
		ClientExtensionResults struct {
			CredProps json.RawMessage `json:"credProps"`
		} `json:"clientExtensionResults"`
	}
	if err := json.Unmarshal(responseJSON, &r); err != nil {
		return nil
	}
	p := &properties{
		AuthenticatorAttachment: r.AuthenticatorAttachment,
		CredentialID:            hex.EncodeToString(decode(r.RawID)),
		PublicKeyAlgorithm:      r.Response.PublicKeyAlgorithm,
		Transports:              r.Response.Transports,
		CredProps:               r.ClientExtensionResults.CredProps,
		ClientData:              clientData(r.Response.ClientDataJSON),
	}
	ad := decode(r.Response.AuthenticatorData)
	if len(ad) == 0 {
		ad = attestationObjectAuthData(decode(r.Response.AttestationObject))
	}
	p.readAuthData(ad)
	// The attested credential data: AAGUID, credential ID, COSE key.
	if len(ad) >= 55 {
		p.AAGUID = hex.EncodeToString(ad[37:53])
		n := int(binary.BigEndian.Uint16(ad[53:55]))
		if len(ad) >= 55+n {
			p.Algorithm = coseAlgorithm(ad[55+n:])
		}
	}
	return p
}

// loginProperties reads a login response, tolerating any shape.
func loginProperties(responseJSON []byte) *properties {
	var r struct {
		RawID                   string `json:"rawId"`
		AuthenticatorAttachment string `json:"authenticatorAttachment"`
		Response                struct {
			ClientDataJSON    string  `json:"clientDataJSON"`
			AuthenticatorData string  `json:"authenticatorData"`
			UserHandle        *string `json:"userHandle"`
		} `json:"response"`
	}
	if err := json.Unmarshal(responseJSON, &r); err != nil {
		return nil
	}
	p := &properties{
		AuthenticatorAttachment: r.AuthenticatorAttachment,
		CredentialID:            hex.EncodeToString(decode(r.RawID)),
		ClientData:              clientData(r.Response.ClientDataJSON),
	}
	if r.Response.UserHandle != nil {
		h := string(decode(*r.Response.UserHandle))
		p.UserHandle = &h
	}
	p.readAuthData(decode(r.Response.AuthenticatorData))
	return p
}

// readAuthData reads the flags and counter of authenticator data.
func (p *properties) readAuthData(ad []byte) {
	if len(ad) < 37 {
		return
	}
	flags := ad[32]
	p.UserPresent = flags&(1<<0) != 0
	p.UserVerified = flags&(1<<2) != 0
	p.BackupEligible = flags&(1<<3) != 0
	p.BackedUp = flags&(1<<4) != 0
	p.ExtensionData = flags&(1<<7) != 0
	p.SignCount = binary.BigEndian.Uint32(ad[33:37])
}

// clientData decodes a base64url clientDataJSON into JSON, or reports
// what it is if it isn't JSON.
func clientData(s string) json.RawMessage {
	cd := decode(s)
	if json.Valid(cd) {
		return cd
	}
	b, _ := json.Marshal(map[string]any{"invalid": string(cd)})
	return b
}

// coseAlgorithm reads the alg of a CTAP2 canonical COSE key: a map whose
// first two pairs are kty (label 1) and alg (label 3).
func coseAlgorithm(b []byte) *int64 {
	pairs, b, ok := cborHead(b, 5)
	if !ok || pairs < 2 {
		return nil
	}
	label, b, ok := cborInt(b)
	if !ok || label != 1 {
		return nil
	}
	if _, b, ok = cborInt(b); !ok { // kty
		return nil
	}
	if label, b, ok = cborInt(b); !ok || label != 3 {
		return nil
	}
	alg, _, ok := cborInt(b)
	if !ok {
		return nil
	}
	return &alg
}

// cborHead reads the head of a CBOR data item of the given major type,
// with an argument of up to 16 bits, and returns the argument.
func cborHead(b []byte, major byte) (arg uint64, rest []byte, ok bool) {
	if len(b) == 0 || b[0]>>5 != major {
		return 0, nil, false
	}
	switch minor := b[0] & 0x1f; {
	case minor < 24:
		return uint64(minor), b[1:], true
	case minor == 24 && len(b) >= 2:
		return uint64(b[1]), b[2:], true
	case minor == 25 && len(b) >= 3:
		return uint64(binary.BigEndian.Uint16(b[1:3])), b[3:], true
	}
	return 0, nil, false
}

// cborInt reads a CBOR integer of either sign.
func cborInt(b []byte) (int64, []byte, bool) {
	if arg, rest, ok := cborHead(b, 0); ok {
		return int64(arg), rest, true
	}
	if arg, rest, ok := cborHead(b, 1); ok {
		return -1 - int64(arg), rest, true
	}
	return 0, nil, false
}

// attestationObjectAuthData lifts the authData member out of an
// attestation object, for a client that sends no authenticatorData: it
// takes the "authData" key and requires the byte string after it to run
// exactly to the end, as it does in the CTAP2 canonical order.
func attestationObjectAuthData(ao []byte) []byte {
	key := []byte("\x68authData")
	i := strings.LastIndex(string(ao), string(key))
	if i < 0 {
		return nil
	}
	b := ao[i+len(key):]
	n, b, ok := cborHead(b, 2)
	if !ok || uint64(len(b)) != n {
		return nil
	}
	return b
}

// decode decodes a base64url field, tolerating padding and the standard
// alphabet, since the point is to record what clients send.
func decode(s string) []byte {
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b
	}
	b, _ := base64.RawStdEncoding.DecodeString(s)
	return b
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func clipError(e *clientError) *clientError {
	if e == nil {
		return &clientError{Name: "unknown", Message: "the client returned nothing"}
	}
	return &clientError{Name: clip(e.Name, 100), Message: clip(e.Message, 1000)}
}

// readJSON reads a JSON request body into v, answering the request if it
// can't.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		http.Error(w, "malformed JSON: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Print(err)
	}
}
