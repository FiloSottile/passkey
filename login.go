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
// optionsJSON is a PublicKeyCredentialRequestOptions object to be passed
// to navigator.credentials.get() as the publicKey field, with an empty
// allowCredentials list. It can be used both for modal and for
// conditional UI (autofill) flows.
//
// request is an opaque value to be stored by the application (see
// [Challenges], and [RequestID] for a storage key) and passed to Login.
//
// Note that a login ceremony is not started for a specific user: the
// user is identified by the response, using [Response.UnauthenticatedUserID].
//
// [Challenges]: #hdr-Challenges
func (rp *RelyingParty) NewLogin() (request, optionsJSON []byte, err error) {
	return rp.newLogin("", nil)
}

// NewLoginForUser begins a login ceremony for a known user, such as a
// re-authentication prompt before a sensitive operation.
//
// The user's passkey records are communicated to the client as
// allowCredentials, so the client offers only that user's credentials
// instead of an account picker. The response is verified with
// [RelyingParty.Login], passing the same records; Login fails if the
// response asserts a user handle other than userID.
func (rp *RelyingParty) NewLoginForUser(userID string, passkeys []string) (request, optionsJSON []byte, err error) {
	if len(userID) == 0 || len(userID) > 64 {
		return nil, nil, errors.New("passkey: invalid user ID")
	}
	return rp.newLogin(userID, passkeys)
}

type requestOptions struct {
	Challenge        string                 `json:"challenge"`
	RPID             string                 `json:"rpId"`
	AllowCredentials []credentialDescriptor `json:"allowCredentials"`
	UserVerification string                 `json:"userVerification"`
	Timeout          int64                  `json:"timeout"`
}

func (rp *RelyingParty) newLogin(userID string, passkeys []string) (request, optionsJSON []byte, err error) {
	allowed, err := credentialDescriptors(passkeys)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: invalid passkey record: %w", err)
	}
	r := newLoginRequest(userID)
	uv := "preferred"
	if rp.requireUserVerification {
		uv = "required"
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
var ErrRequestExpired = errors.New("passkey: login request expired")

// ErrUnknownCredential is returned by [RelyingParty.Login] when the
// response asserts a credential that is not among the provided passkey
// records. It can be surfaced to the user as "this passkey was removed
// from the account".
//
// It is necessarily reported before signature verification, so exposing
// it to clients reveals whether a credential ID is registered for the
// asserted user.
var ErrUnknownCredential = errors.New("passkey: credential not registered for this user")

// ErrUserVerificationRequired is returned by [RelyingParty.Login] when
// the response is valid but user verification was not performed and
// [Options.RequireUserVerification] is set. It can be surfaced to the
// user as "this passkey doesn't support the verification required by
// this account", with the option to use a different passkey or
// register this one anew. The login has still failed: applications
// that want to accept such logins with reduced trust should leave
// RequireUserVerification unset and check [Response.UserVerified]
// instead.
var ErrUserVerificationRequired = errors.New("passkey: user verification required but not performed")

// Login verifies a login response against the request returned by
// [RelyingParty.NewLogin] and the given user's passkey records.
//
// On success, it returns the index in passkeys of the record the
// response was verified against.
//
// Login verifies that the signature is valid, with the matched record's
// public key, over the authenticator data and the hash of the client
// data; that the client data is well-formed JSON with type
// "webauthn.get", the request's challenge, the expected origin, and
// crossOrigin absent or false; that the authenticator data carries the
// hash of the RP ID and has the user presence flag set (and the user
// verification flag, if [Options.RequireUserVerification] is set); that
// the request has not expired; and that the asserted user handle, if
// present, matches the request for user-scoped ceremonies.
//
// The signature counter is not checked (it is zero for the major
// passkey providers), and the response's backup and user verification
// flags can be inspected with [Response.BackedUp] and
// [Response.UserVerified].
//
// Failures that call for special handling return sentinel errors and are
// documented below. All other errors should be logged but not exposed
// to the user.
//
// If the response is valid but its credential ID matches none of
// passkeys, Login returns [ErrUnknownCredential]: the user asserted a
// credential the server no longer (or never) had a record of, for
// example one deleted from account settings but still present in the
// user's passkey provider.
//
// If the response is valid but user verification was not performed
// while [Options.RequireUserVerification] is set, Login returns
// [ErrUserVerificationRequired], for example when the requirement was
// enabled after a credential incapable of user verification was
// registered.
//
// If the response is valid but the request is older than
// [Options.Timeout], Login returns [ErrRequestExpired]: the
// application can transparently retry with a fresh request, which is
// routine for conditional UI (autofill) prompts left idle.
func (rp *RelyingParty) Login(response *Response, request []byte, passkeys []string) (matched int, err error) {
	if response == nil {
		return 0, errors.New("passkey: response is nil")
	}
	req, err := parseLoginRequest(request)
	if err != nil {
		return 0, err
	}

	if response.challenge != req.challenge {
		return 0, errors.New("passkey: client data challenge does not match the request")
	}
	if response.origin != rp.origin {
		return 0, fmt.Errorf("passkey: origin %q is not the expected value %q", response.origin, rp.origin)
	}
	if response.rpIDHash != sha256.Sum256([]byte(rp.rpID)) {
		return 0, errors.New("passkey: assertion for a different RP ID")
	}
	if response.userID != "" && req.userID != "" && response.userID != req.userID {
		return 0, errors.New("passkey: assertion is for a different user than the request")
	}

	var key crypto.PublicKey
	for i, p := range passkeys {
		r, err := parseRecord(p)
		if err != nil {
			return 0, fmt.Errorf("%w (record #%d)", err, i)
		}
		if bytes.Equal(r.credentialID, response.credentialID) {
			key = r.key
			matched = i
		}
		// Continue iterating over passkeys, to report an error if any are invalid.
	}
	if key == nil {
		return 0, ErrUnknownCredential
	}

	message := make([]byte, 0, len(response.authData)+len(response.clientDataHash))
	message = append(message, response.authData...)
	message = append(message, response.clientDataHash[:]...)
	switch key := key.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(message)
		if !ecdsa.VerifyASN1(key, digest[:], response.signature) {
			return 0, errors.New("passkey: ECDSA signature verification failed")
		}
	case *rsa.PublicKey:
		digest := sha256.Sum256(message)
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], response.signature); err != nil {
			return 0, errors.New("passkey: RSA signature verification failed")
		}
	case *mldsa.PublicKey:
		if err := mldsa.Verify(key, message, response.signature, nil); err != nil {
			return 0, errors.New("passkey: ML-DSA signature verification failed")
		}
	default:
		return 0, errors.New("passkey: internal error: unsupported public key type")
	}

	if time.Since(req.created) > rp.timeout {
		return 0, ErrRequestExpired
	}
	if rp.requireUserVerification && response.userVerified {
		return 0, ErrUserVerificationRequired
	}

	return matched, nil
}
