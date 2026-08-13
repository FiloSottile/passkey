// Package passkey implements the server (Relying Party) side of WebAuthn
// for discoverable credentials (passkeys).
//
// The package is built around [passkey records]: opaque strings, handled
// like prefixed password hashes, that encode everything the server needs
// to store about a credential.
//
//	$webauthn$v=1$transports=hybrid+internal$<base64 authenticator data>
//
// Records are immutable: they are produced by [RelyingParty.Register] and never
// change afterwards. Mutable authenticator state (like backup state and User
// Verification) is not tracked; per-login values can be read from the assertion
// response with [Response.BackedUp] and [Response.UserVerified].
//
// # Storage model
//
// Applications are expected to store passkey records in a table keyed
// only by user ID, for example
//
//	CREATE TABLE passkeys (
//	    user_id TEXT NOT NULL,
//	    record  TEXT NOT NULL,
//	    FOREIGN KEY(user_id) REFERENCES users(passkeys_user_id)
//	);
//	CREATE INDEX passkeys_user_id ON passkeys(user_id);
//
// with no index on credential IDs and no uniqueness constraints. No
// other columns are needed by this package; applications may add their
// own (e.g. a nickname, creation time, or last-used time for a
// passkey management UI). Lookups always resolve the user first (from the session
// during registration, from [Response.UnauthenticatedUserID] during login)
// and then pass all of the user's records to [RelyingParty.Login], which
// selects the right one.
//
// (Because credentials are never resolved by credential ID across
// accounts, a credential ID registered maliciously into one account can
// never affect authentication for another, and the cross-account
// uniqueness check recommended by the WebAuthn specification becomes
// unnecessary.)
//
// # User IDs
//
// User IDs are opaque strings, at most 64 bytes. They
// are stored inside the authenticator and returned in every login, so
// they MUST NOT contain personal information such as usernames or email
// addresses, and they cannot be changed later. Generate them with
// [crypto/rand.Text] at account creation and map them to accounts in the
// database. Do not reuse internal account identifiers.
//
// For example
//
//	ALTER TABLE users ADD COLUMN passkeys_user_id TEXT;
//	CREATE UNIQUE INDEX users_passkeys_user_id ON users(passkeys_user_id);
//
// # Challenges
//
// [RelyingParty.NewLogin] and [RelyingParty.NewLoginForUser] return an
// opaque request value that must be presented back to [RelyingParty.Login].
//
// The application must:
//
//   - store the request, either server-side (in memory or in a KV
//     store, keyed by [RequestID]) or client-side in a cookie;
//   - if possible, delete it after use, so that each request is
//     accepted at most once (client-side storage can't enforce this:
//     an attacker who captured both request and response can replay
//     the login until the request expires); and
//   - protect its integrity if stored client-side (e.g. with an
//     authenticated cookie), as a forged request could defeat
//     challenge freshness.
//
// Requests expire [Options.Timeout] after creation (which [RequestCreation]
// returns), and the application can use the same window as the lifetime of
// stored requests (e.g. as the KV TTL or cookie Max-Age).
//
// Request values don't need to be kept secret but must be protected
// from tampering.
//
// (Registration has no request value: with attestation "none", no part of a
// registration response is signed by a party the server trusts, so a
// registration challenge can't prove freshness and is not verified.
// Applications tie a registration to the signed-in session, and must protect
// the registration endpoint with their usual session and cross-site request
// forgery defenses, like any other authenticated endpoint.)
//
// [passkey records]: https://c2sp.org/passkey-record
package passkey

import (
	"errors"
	"math"
	"net"
	"strings"
	"time"
)

// Options configures a [RelyingParty].
type Options struct {
	// RPID is the Relying Party ID. The RP ID scopes which credentials exist
	// for an origin, it is stored in every credential, and it can never change.
	//
	// Generally, the registrable domain of the site (e.g. example.com) is a
	// good RP ID.
	RPID string

	// Origin is the origin from which registrations and logins are accepted. It
	// gates where ceremonies may be performed, and can change freely, for
	// example when sign-in moves to a different subdomain.
	//
	// It must match exactly the origin of the page that calls
	// navigator.credentials.create() or navigator.credentials.get(), or the
	// platform-specific equivalent. NewRelyingParty rejects many values that
	// could never match a serialized origin, such as ones that are not
	// lowercase or that have a path.
	//
	// Examples of valid origins are "https://accounts.example.com" and
	// "https://example.com:8443" and "android:apk-key-hash:...".
	//
	// Origin may be outside the RP ID's domain, if authorized through Related
	// Origin Requests (the /.well-known/webauthn document, which the
	// application is responsible for serving).
	//
	// If the application accepts ceremonies from multiple origins, it
	// creates a RelyingParty per origin with the same RPID, selected by
	// the endpoint handling the request, never from request headers.
	// The same pattern serves any per-context setting: RelyingParty
	// values are cheap, e.g. make one with RequireUserVerification set
	// for re-authentication prompts.
	Origin string

	// RequireUserVerification causes Login to fail with
	// [ErrUserVerificationRequired] unless the authenticator performed
	// user verification (e.g. PIN or biometrics). NewLogin and
	// NewLoginForUser then request userVerification: "required", so
	// clients prompt for verification rather than return an assertion
	// that would be rejected. It also causes NewRegistration to request
	// userVerification: "required", so that clients fail credential
	// creation on authenticators that can't satisfy it, rather than
	// registering a credential that can never log in. Register itself
	// does not check the user verification flag, so that conditional
	// (automatic) passkey creation keeps working.
	//
	// If false (the default), user verification is requested but not
	// required, and its result can be checked with
	// [Response.UserVerified].
	RequireUserVerification bool

	// Timeout is how long a request returned by NewLogin or
	// NewLoginForUser remains valid: Login rejects responses to
	// expired requests. It is also communicated to the client as a
	// ceremony timeout hint (for both registration and login), and is
	// the recommended lifetime for requests stored by the application.
	//
	// If zero, it defaults to five minutes. Conditional UI (autofill)
	// logins may warrant a longer timeout, as the prompt can sit idle
	// for a while before the user engages with it.
	Timeout time.Duration
}

// RelyingParty verifies registrations and logins. It holds no state about
// registered passkeys or ongoing login ceremonies.
//
// Its methods are safe for concurrent use by multiple goroutines.
type RelyingParty struct {
	rpID                    string
	origin                  string
	requireUserVerification bool
	timeout                 time.Duration
}

// NewRelyingParty returns a RelyingParty configured with the given options.
//
// [Options.RPID] and [Options.Origin] must be set.
func NewRelyingParty(opts *Options) (*RelyingParty, error) {
	if opts == nil {
		return nil, errors.New("passkey: Options is nil")
	}

	if opts.RPID == "" {
		return nil, errors.New("passkey: RP ID is empty")
	}
	if len(opts.RPID) > 255 {
		return nil, errors.New("passkey: RP ID is too long")
	}
	for label := range strings.SplitSeq(opts.RPID, ".") {
		if label == "" {
			return nil, errors.New("passkey: invalid RP ID")
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			default:
				return nil, errors.New("passkey: invalid RP ID; " +
					"it must be a bare domain")
			}
		}
	}
	if net.ParseIP(opts.RPID) != nil {
		return nil, errors.New("passkey: invalid RP ID; " +
			"it must be a domain, not an IP address")
	}

	if opts.Origin == "" {
		return nil, errors.New("passkey: Origin is empty")
	}
	if !strings.ContainsRune(opts.Origin, ':') {
		return nil, errors.New("passkey: invalid Origin; it must include an origin")
	}
	if strings.ContainsRune(opts.Origin, '*') {
		return nil, errors.New(`passkey: Origin contains "*": wildcard origins are not supported`)
	}
	if scheme, rest, ok := strings.Cut(opts.Origin, "://"); ok {
		if scheme == "" || rest == "" {
			return nil, errors.New("passkey: invalid Origin; " +
				"it must be canonical, without path")
		}
		for _, c := range scheme + rest {
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == ':':
			default:
				return nil, errors.New("passkey: invalid Origin; " +
					"it must be canonical, without path")
			}
		}
	}

	timeout := opts.Timeout
	switch {
	case timeout < 0:
		return nil, errors.New("passkey: Timeout is negative")
	case timeout.Milliseconds() > math.MaxUint32:
		// Clients coerce the timeout hint to a WebIDL unsigned long.
		return nil, errors.New("passkey: Timeout is too large")
	case timeout == 0:
		timeout = 5 * time.Minute
	}

	return &RelyingParty{
		rpID:                    opts.RPID,
		origin:                  opts.Origin,
		requireUserVerification: opts.RequireUserVerification,
		timeout:                 timeout,
	}, nil
}
