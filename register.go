package passkey

// User identifies the account a passkey is being registered for.
type User struct {
	// ID is the opaque user ID; see [User IDs].
	//
	// [User IDs]: #hdr-User_IDs
	ID string

	// Name is a human-readable identifier for the account, such as a
	// username or email address. It is displayed in credential pickers
	// and stored by the authenticator, but never returned to the server
	// or used in the protocol. It is also sent as the WebAuthn
	// displayName, which credential providers ignore in practice.
	Name string
}

// NewRegistration begins the registration of a new passkey for user.
//
// passkeys is the user's full list of existing passkey records, or nil
// if the user has none. They are communicated to the client as
// excludeCredentials, so an authenticator that already holds one of
// them for this RP will refuse to create a new credential, and the
// user won't end up with duplicate passkeys on the same authenticator.
//
// optionsJSON is a PublicKeyCredentialCreationOptions object to be
// passed to navigator.credentials.create() as the publicKey field,
// requesting a discoverable credential (residentKey: "required") with
// attestation "none" and the credProps extension (which reports back
// whether the created credential is actually discoverable). The requested
// algorithms are, in order of preference, ML-DSA-44, ES256, and RS256.
//
// Registration is stateless for the server: there is no request value
// to store, and the response is verified by [RelyingParty.Register].
func (rp *RelyingParty) NewRegistration(user User, passkeys []string) (optionsJSON []byte, err error)

// Register verifies a registration response and, on success, returns
// the new passkey record, to be stored for the signed-in user whose
// session initiated the registration.
//
// responseJSON is the JSON serialization of the PublicKeyCredential
// returned by navigator.credentials.create() (as produced by its
// toJSON() method).
//
// Register fails if the response reports (via the credProps extension)
// that the created credential is not discoverable. Absence of the
// extension output is accepted: some clients (notably Safari) never
// report it, and enforcement of discoverability rests on the client's
// residentKey: "required" obligation.
//
// Register does not require the user presence or user verification
// flags, so that conditional (automatic) passkey creation flows, in
// which the user does not interact with a prompt, are supported. User
// verification is enforced, per [Options.RequireUserVerification], at
// login.
//
// Register verifies that the client data is well-formed JSON with type
// "webauthn.create" and the expected origin, and that the authenticator
// data carries the hash of the RP ID. The challenge is not verified;
// see the Challenges section of the package documentation.
func (rp *RelyingParty) Register(responseJSON []byte) (passkey string, err error)
