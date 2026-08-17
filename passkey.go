// Package passkey implements the server (Relying Party) side of WebAuthn
// for discoverable credentials (passkeys).
//
// Although WebAuthn supports a range of purposes and policies, this package
// is designed for password-less authentication with discoverable credentials:
// i.e. logging into an account with a passkey.
//
// The package is built around [passkey records]: opaque strings, handled
// like prefixed password hashes, that encode everything the server needs
// to store about a credential.
//
//	$webauthn$v=1$transports=hybrid+internal$<base64 authenticator data>
//
// Records are immutable: they are produced by [RelyingParty.Register] and never
// change afterwards. Mutable authenticator state (like backup state) is not
// tracked; per-login values are reported by [RelyingParty.Login] as
// [LoginResult.BackedUp] and [LoginResult.UserVerified].
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
// passkey management UI). Lookups always resolve the user first (from the
// session during registration, from [Response.UnauthenticatedUserID] or the
// session during login) and then pass all of the user's records to
// [RelyingParty.Login], which selects the right one.
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
// [RelyingParty.NewLogin] and [RelyingParty.NewLoginWithCredentials] return an
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
// # WebAuthn interface details
//
// Registration options request a discoverable credential
// (residentKey: "required") with user verification "preferred",
// attestation "none", and the credProps extension.
//
// The requested algorithms are, in order of preference, ML-DSA-44, ES256, and RS256.
//
// The user name is also sent as the displayName, which credential providers
// ignore in practice.
//
// Register fails if the response reports (via the credProps extension)
// that the created credential is not discoverable. Absence of the
// extension output is accepted: some clients (notably Safari) never
// report it, and enforcement of discoverability rests on the client's
// residentKey: "required" obligation.
//
// Register does not require the user presence flag, so that conditional
// (automatic) passkey creation flows, in which the user does not
// interact with a prompt, are supported.
//
// Register verifies that the client data is well-formed JSON with type
// "webauthn.create", the expected origin, and crossOrigin absent or false;
// that the authenticator data carries the hash of the RP ID; and, unless
// [Options.OptionalUserVerification] is set, that user verification is set
// up on the authenticator (see the User verification section below). The
// challenge is not verified; see the Challenges section above.
//
// Login options request user verification "required", or "preferred" if
// [Options.OptionalUserVerification] is set. [RelyingParty.NewLogin] sends
// an empty allowCredentials list; [RelyingParty.NewLoginWithCredentials]
// populates it with the user's credentials instead.
//
// Credential descriptors, in excludeCredentials at registration and in
// allowCredentials at login, carry the transports recorded at registration
// (see [Transports]), which help the client reach the right authenticator.
//
// Both registration and login options carry [Options.Timeout] as the
// ceremony timeout hint.
//
// Login verifies that the signature is valid, with the matched record's
// public key, over the authenticator data and the hash of the client
// data; that the client data is well-formed JSON with type
// "webauthn.get", the request's challenge, the expected origin, and
// crossOrigin absent or false; that the authenticator data carries the
// hash of the RP ID (as does the matched record) and has the user
// presence flag set; that the request has not expired; and, unless
// [Options.OptionalUserVerification] is set, that user verification was
// performed and can be relied upon (see the User verification section
// below).
//
// The signature counter is not checked (it is zero for the major
// passkey providers).
//
// # User verification
//
// The UV flag of a login assertion is relied upon (and
// [LoginResult.UserVerified] is set) only if the matched record has the UV or
// the BE flag, i.e. if user verification was performed at registration or the
// credential is a synced passkey. Otherwise, it suggests the credential was
// stored on an external authenticator without UV set up, and an attacker that
// were to steal it could have set up their own PIN to enable UV.
//
// By default, login options request user verification "required", and Login
// fails unless [LoginResult.UserVerified] would be true: with
// [ErrUserVerificationUnavailable] if the record has neither the UV nor the BE
// flag (likely a security key without a PIN), and with a generic error
// otherwise. Registration options request "preferred", to allow conditional
// (automatic) passkey creation, but Register fails with
// [ErrUserVerificationUnavailable] if the response has neither the UV nor the
// BE flag, as the credential could never log in.
//
// If [Options.OptionalUserVerification] is set, login options request
// "preferred", Register and Login accept responses regardless of the flags,
// and [LoginResult.UserVerified] retains the same semantics.
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

	// Origin is the origin from which registrations and logins are expected and
	// allowed. It can change over time or across endpoints.
	//
	// It must match exactly the origin of the page that calls
	// navigator.credentials.create() or navigator.credentials.get(), or the
	// platform-specific equivalent.
	//
	// Examples of valid origins are "https://example.com" and
	// "https://accounts.example.com:8443" and "android:apk-key-hash:...".
	//
	// Origin may be outside the RP ID's domain, if authorized through Related
	// Origin Requests (the /.well-known/webauthn document, which the
	// application is responsible for serving).
	//
	// To accept ceremonies from multiple origins, create a RelyingParty per
	// origin, and select it based on the endpoint handling the request.
	Origin string

	// OptionalUserVerification disables the user verification (e.g. PIN or
	// biometrics) requirement. This is mostly appropriate if a passkey is a
	// second factor used alongside e.g. a password.
	//
	// By default, login ceremonies require user verification and Login fails
	// unless it was performed and can be relied upon.
	// If OptionalUserVerification is true, login ceremonies request user
	// verification but don't require it. Applications can consult
	// [LoginResult.UserVerified], which retains the same semantics.
	//
	// Registration ceremonies never require user verification, but by default
	// Register rejects credentials that are not capable of it.
	// If OptionalUserVerification is true, Register will accept some rare
	// credentials that will only work for logins with OptionalUserVerification.
	OptionalUserVerification bool

	// Timeout is how long a request returned by NewLogin or
	// NewLoginWithCredentials remains valid.
	//
	// If zero, it defaults to five minutes. Conditional UI (autofill)
	// logins may warrant a longer timeout, as the prompt can sit idle
	// for a while before the user engages with it.
	Timeout time.Duration
}

// A RelyingParty verifies registrations and logins. It holds no state about
// registered passkeys or ongoing login ceremonies.
//
// Its methods are safe for concurrent use by multiple goroutines.
type RelyingParty struct {
	rpID                     string
	origin                   string
	optionalUserVerification bool
	timeout                  time.Duration
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
		rpID:                     opts.RPID,
		origin:                   opts.Origin,
		optionalUserVerification: opts.OptionalUserVerification,
		timeout:                  timeout,
	}, nil
}
