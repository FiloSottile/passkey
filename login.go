package passkey

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
func (rp *RelyingParty) NewLogin() (request, optionsJSON []byte, err error)

// NewLoginForUser begins a login ceremony for a known user, such as a
// re-authentication prompt before a sensitive operation.
//
// The user's passkey records are communicated to the client as
// allowCredentials, so the client offers only that user's credentials
// instead of an account picker. The response is verified with
// [RelyingParty.Login], passing the same records; Login fails if the
// response asserts a user handle other than userID.
func (rp *RelyingParty) NewLoginForUser(userID string, passkeys []string) (request, optionsJSON []byte, err error)

// ErrRequestExpired is returned by [RelyingParty.Login] when the
// response is valid but the request was created more than
// [Options.Timeout] ago. Applications should discard the request and
// retry the ceremony with a fresh one.
var ErrRequestExpired error

// ErrUnknownCredential is returned by [RelyingParty.Login] when the
// response asserts a credential that is not among the provided passkey
// records. It can be surfaced to the user as "this passkey was removed
// from the account".
//
// It is necessarily reported before signature verification, so exposing
// it to clients reveals whether a credential ID is registered for the
// asserted user.
var ErrUnknownCredential error

// ErrUserVerificationRequired is returned by [RelyingParty.Login] when
// the response is valid but user verification was not performed and
// [Options.RequireUserVerification] is set. It can be surfaced to the
// user as "this passkey doesn't support the verification required by
// this account", with the option to use a different passkey or
// register this one anew. The login has still failed: applications
// that want to accept such logins with reduced trust should leave
// RequireUserVerification unset and check [Response.UserVerified]
// instead.
var ErrUserVerificationRequired error

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
// Most failures are reported as generic errors, with details for
// logging: the correct application behavior is the same for all of
// them. Three failures that call for distinct handling are reported as
// sentinel errors, documented below; they explain why a login failed,
// for the application's benefit, and none of them mean the login can
// be treated as successful.
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
func (rp *RelyingParty) Login(response *Response, request []byte, passkeys []string) (matched int, err error)
