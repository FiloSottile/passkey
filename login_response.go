package passkey

// Response is a parsed PublicKeyCredential returned by
// navigator.credentials.get().
//
// It is NOT verified until it is passed to [RelyingParty.Login] and Login
// succeeds. It is meant to be used for looking up the request and the user's
// passkey records.
type Response struct {
	// contains filtered or unexported fields
}

// ParseResponse parses a login response into a [Response].
//
// responseJSON is the JSON serialization of the PublicKeyCredential returned by
// navigator.credentials.get() (as produced by its toJSON() method).
//
// It does not verify the response: use [RelyingParty.Login] to verify it
// against the request and the user's passkey records.
func ParseResponse(responseJSON []byte) (*Response, error)

// BackedUp reports whether the credential asserts it is currently backed up,
// according to the login response. It can be checked after a successful
// [RelyingParty.Login] to inform account recovery decisions.
func (r *Response) BackedUp() bool

// RequestID returns the unique identifier of the request this response
// is for, as returned by [RequestID] when the request was created. It can
// be used to look up the stored request.
func (r *Response) RequestID() string

// UnauthenticatedUserID returns the user ID asserted by this response.
//
// This user ID is attacker-controlled until the response is verified with
// [RelyingParty.Login], and must not be used for anything but looking up
// the user's passkey records.
//
// The return value may be empty for responses to [RelyingParty.NewLoginForUser]
// ceremonies, where the application already knows the user.
func (r *Response) UnauthenticatedUserID() string

// UserVerified reports whether user verification was performed,
// according to a login response. It can be checked after a successful
// [RelyingParty.Login] to gate sensitive operations.
func (r *Response) UserVerified() bool
