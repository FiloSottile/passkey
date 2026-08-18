package passkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"filippo.io/mldsa"
)

// NewLogin begins a login ceremony.
//
// optionsJSON is a PublicKeyCredentialRequestOptions object to be
//
//  1. parsed from JSON on the client side, then
//  2. passed to PublicKeyCredential.parseRequestOptionsFromJSON(), and then
//  3. passed to navigator.credentials.get() as the publicKey field.
//
// It can be used both for modal and for conditional UI (autofill) flows.
//
// request is an opaque value to be stored by the application (see
// [Challenges], and [RequestID] for a storage key) and passed to Login.
//
// Note that a login ceremony is not started for a specific user: the
// user is identified by the response, using [Response.UnauthenticatedUserID].
//
// [Challenges]: #hdr-Challenges
func (rp *RelyingParty) NewLogin() (request, optionsJSON []byte, err error) {
	return rp.NewLoginWithOptions(nil)
}

// LoginOptions configures the behavior of [RelyingParty.NewLoginWithOptions].
//
// The zero value is a valid configuration, and is equivalent to calling [RelyingParty.NewLogin].
type LoginOptions struct {
	// AllowCredentials is a list of passkey records for a user that the application
	// has already identified. It can be used e.g. for a re-authentication
	// prompt before a sensitive operation in a signed-in session.
	//
	// The user's passkey records are communicated to the client so it
	// offers only that user's credentials instead of an account picker.
	// The user is identified by the application, not by the response:
	// [Response.UnauthenticatedUserID] is empty when AllowCredentials is set,
	// and the application must look up the user's records the same way
	// it did to populate this field (e.g. from the session) and pass
	// them to [RelyingParty.Login].
	//
	// The login options disclose the user's credential IDs to whoever receives it,
	// so this field should be nil for a fully unauthenticated username.
	AllowCredentials []string
}

type requestOptions struct {
	Challenge        string                 `json:"challenge"`
	RPID             string                 `json:"rpId"`
	AllowCredentials []credentialDescriptor `json:"allowCredentials"`
	UserVerification string                 `json:"userVerification"`
	Timeout          int64                  `json:"timeout"`
}

// NewLoginWithOptions begins a login ceremony with the given options.
//
// If options is nil or the zero value, it is equivalent to calling
// [RelyingParty.NewLogin].
func (rp *RelyingParty) NewLoginWithOptions(options *LoginOptions) (request, optionsJSON []byte, err error) {
	if options == nil {
		options = &LoginOptions{}
	}
	allowed := credentialDescriptors(options.AllowCredentials)
	r := newLoginRequest(len(options.AllowCredentials) > 0)
	uv := "required"
	if rp.optionalUserVerification {
		uv = "preferred"
	}
	optionsJSON, err = json.Marshal(requestOptions{
		Challenge:        base64.RawURLEncoding.EncodeToString(r.challenge[:]),
		RPID:             rp.rpID,
		AllowCredentials: allowed,
		UserVerification: uv,
		Timeout:          rp.timeout.Milliseconds(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: error encoding JSON: %w", err)
	}
	return r.Bytes(), optionsJSON, nil
}

// ErrRequestExpired is returned by [RelyingParty.Login] when the
// response is valid but the request was created more than
// [Options.Timeout] ago. Applications should discard the request and
// retry the ceremony with a fresh one.
//
// It is always wrapped, so callers must use [errors.Is].
var ErrRequestExpired = errors.New("passkey: login request expired")

// ErrUnknownCredential is returned by [RelyingParty.Login] when the
// response asserts a credential that is not among the provided passkey
// records. It can be surfaced to the user as "this passkey was removed
// from the account".
//
// It is always wrapped, so callers must use [errors.Is].
var ErrUnknownCredential = errors.New("passkey: credential not registered for this user")

// ErrUserVerificationUnavailable is returned by [RelyingParty.Register] and
// [RelyingParty.Login] when the response is valid, but the passkey can't
// provide user verification (e.g. PIN or biometrics) that can be relied upon.
// It is never returned if [Options.OptionalUserVerification] is set.
//
// If returned by Register, the authenticator is likely a security key without a
// PIN. It can be surfaced to the user as "this passkey can't verify it's you",
// suggesting they configure a PIN on their security key or use a different
// passkey authenticator.
//
// If returned by Login, the matched record was generated with
// [Options.OptionalUserVerification] or imported. It requires replacing the
// passkey with a new registration, potentially after the user has configured a
// PIN on their security key.
//
// It is always wrapped, so callers must use [errors.Is].
var ErrUserVerificationUnavailable = errors.New("passkey: user verification unavailable")

// LoginResult is returned by [RelyingParty.Login] on a successful login.
//
// Unlike the [Response] methods, which return attacker-controlled
// lookup keys, LoginResult fields are authenticated.
type LoginResult struct {
	// Matched is the index in passkeys of the record the response
	// was verified against.
	Matched int

	// UserVerified reports whether user verification (e.g. PIN or
	// biometrics) was performed and can be relied upon.
	UserVerified bool

	// BackedUp reports whether the credential asserts it is currently
	// backed up (e.g. synced to a cloud account). It can inform prompting
	// the user to remove their password from the account, if any.
	BackedUp bool
}

// Login verifies a login response against the request returned by
// [RelyingParty.NewLogin] and the given user's passkey records.
//
// On success, it returns a [LoginResult] reporting the index in passkeys
// of the record the response was verified against.
//
// Failures that call for special handling return sentinel errors and are
// documented below. All other errors should be logged but not exposed
// to the user.
//
//   - If the response is valid but matches none of
//     passkeys, Login returns [ErrUnknownCredential]: the user asserted a
//     credential the server no longer (or never) had a record of, for
//     example one deleted from account settings but still present in the
//     user's passkey provider.
//
//   - If the response is valid but the matched record suggests user
//     verification can't be relied upon, Login returns
//     [ErrUserVerificationUnavailable] unless
//     [Options.OptionalUserVerification] is set.
//
//   - If the response is valid but the request is older than
//     [Options.Timeout], Login returns [ErrRequestExpired]: the
//     application can transparently retry with a fresh request, which is
//     routine for conditional UI (autofill) prompts left idle.
func (rp *RelyingParty) Login(response *Response, request []byte, passkeys []string) (*LoginResult, error) {
	if response == nil {
		return nil, errors.New("passkey: response is nil")
	}
	req, err := parseLoginRequest(request)
	if err != nil {
		return nil, err
	}

	if response.challenge != req.challenge {
		return nil, errors.New("passkey: client data challenge does not match the request")
	}
	if response.origin != rp.origin {
		return nil, fmt.Errorf("passkey: origin %q is not the expected value %q", response.origin, rp.origin)
	}
	rpIDHash := sha256.Sum256([]byte(rp.rpID))
	if response.rpIDHash != rpIDHash {
		return nil, errors.New("passkey: assertion for a different RP ID")
	}

	message := make([]byte, 0, len(response.authData)+len(response.clientDataHash))
	message = append(message, response.authData...)
	message = append(message, response.clientDataHash[:]...)

	var result *LoginResult
	var skipped, signatureErrors []error
	for i, p := range passkeys {
		r, err := parseRecord(p)
		if err != nil {
			// Continue iterating, to avoid locking out an account
			// due to a single bad record.
			skipped = append(skipped, fmt.Errorf("%w (record #%d)", err, i))
			continue
		}
		if r.rpIDHash != rpIDHash {
			skipped = append(skipped, fmt.Errorf("record for a different RP ID (record #%d)", i))
			continue
		}
		if !bytes.Equal(r.credentialID, response.credentialID) {
			continue
		}
		if verifySignature(r.key, message, response.signature) {
			if time.Since(req.created) > rp.timeout {
				return nil, fmt.Errorf("%w: request created at %v", ErrRequestExpired, req.created)
			}

			// WebAuthn L3, Section 4 (see uvInitialized) insists that the UV
			// flag can be relied upon only if the credential was previously
			// observed with UV in a trusted context, either at registration or
			// during a login with an additional factor.
			//
			// The reason is to prevent an attack where an authenticator did not
			// have UV at registration, and then the attacker steals it and
			// configures their own PIN.
			//
			// The problem with this is that 1. it would require storing a
			// separate mutable boolean per record, or updating the record upon
			// (certain) logins, and 2. it defeats the point of UV-less
			// conditional registration. (If a UV+password login is required to
			// "upgrade" the record to a passwordless credential, then might as
			// well just require UV at registration.)
			//
			// Ideally, a credProps field would be introduced to communicate
			// what actually matters for security: whether the authenticator has
			// UV *set up*, not whether UV was obtained during registration.
			//
			// In the meantime, since the attack scenario only affects external
			// authenticators (security keys), we relax the requirement for
			// Backup Eligible credentials, which can't be produced by external
			// authenticators.
			//
			// We could also rely on the fact that registering resident
			// credentials requires UV on most external authenticators (and/or
			// is enforced by most browsers when using external authenticators),
			// but 1. that's not guaranteed by the specification, and 2. a
			// record could be imported from a system that does not require
			// resident credentials. On the other hand, this fact means
			// uvSetUpAtRegistration will almost universally be true.
			//
			// See https://go.dev/issue/80663.
			uvSetUpAtRegistration := r.flags.userVerified() || r.flags.backupEligible()
			result = &LoginResult{
				Matched:      i,
				UserVerified: response.flags.userVerified() && uvSetUpAtRegistration,
				BackedUp:     response.flags.backupState(),
			}
			if !rp.optionalUserVerification && !result.UserVerified {
				if !uvSetUpAtRegistration {
					return nil, fmt.Errorf("%w: the matched record has neither the UV nor the BE flag, "+
						"so user verification can't be relied upon", ErrUserVerificationUnavailable)
				}
				return nil, errors.New("passkey: assertion has no user verification flag: " +
					"the client did not honor the required user verification, or the request " +
					"options were produced with a different OptionalUserVerification setting")
			}

			return result, nil
		}
		// Continue iterating, in case two records have the same
		// credential ID but different keys, and the one that actually
		// signed the assertion is later in the list.
		signatureErrors = append(signatureErrors,
			fmt.Errorf("signature verification failed (record #%d)", i))
	}

	switch {
	case len(signatureErrors) == 1:
		return nil, fmt.Errorf("passkey: %v", signatureErrors[0])
	case len(signatureErrors) > 1:
		return nil, fmt.Errorf("passkey: multiple records matched the credential ID but none verified the signature: %v", signatureErrors)
	case len(skipped) > 0:
		return nil, fmt.Errorf("%w, and some records were skipped: %v", ErrUnknownCredential, skipped)
	default:
		return nil, fmt.Errorf("%w", ErrUnknownCredential)
	}
}

func verifySignature(key crypto.PublicKey, message, sig []byte) bool {
	switch key := key.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(message)
		return ecdsa.VerifyASN1(key, digest[:], sig)
	case *rsa.PublicKey:
		digest := sha256.Sum256(message)
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) == nil
	case *mldsa.PublicKey:
		return mldsa.Verify(key, message, sig, nil) == nil
	default:
		return false
	}
}
