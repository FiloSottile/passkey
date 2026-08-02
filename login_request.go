package passkey

// RequestID returns a unique identifier for a request returned by
// [RelyingParty.NewLogin] or [RelyingParty.NewLoginForUser], to be used
// as a storage key. The same value is returned by [Response.RequestID]
// for the corresponding response.
//
// If the request is invalid, RequestID returns an empty string.
func RequestID(request []byte) string
