package passkey

// AAGUID returns the authenticator's AAGUID from a passkey record, which
// may identify the passkey provider (e.g. for display purposes, using
// the community-maintained AAGUID lists). It is all zeroes if the
// authenticator did not provide one.
func AAGUID(passkey string) ([16]byte, error)

// BackedUp reports whether the credential was backed up (e.g. synced to
// a cloud account) at registration time. For the current state, check
// login responses with [Response.BackedUp].
func BackedUp(passkey string) (bool, error)

// CredentialID returns the credential ID of a passkey record.
//
// It is not needed for the flows implemented by this package, and is
// provided for interoperability: exporting credentials, importing them
// into systems that look credentials up by ID, and building UIs that
// need a stable per-credential identifier.
func CredentialID(passkey string) ([]byte, error)

// Transports returns the transport hints recorded at registration
// (e.g. "internal", "hybrid", "usb"). They are used to populate the
// credential descriptors sent to clients by
// [RelyingParty.NewRegistration] and [RelyingParty.NewLoginForUser],
// where they help the client reach the right authenticator during
// login; they are exposed for interoperability and diagnostics.
func Transports(passkey string) ([]string, error)
