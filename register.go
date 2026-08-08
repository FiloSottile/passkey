package passkey

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

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

type pubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int32  `json:"alg"`
}

// supportedAlgorithms is the pubKeyCredParams list, in order of preference.
var supportedAlgorithms = []pubKeyCredParam{
	{Type: "public-key", Alg: algMLDSA44},
	{Type: "public-key", Alg: algES256},
	{Type: "public-key", Alg: algRS256},
}

type creationOptions struct {
	RP struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"rp"`
	User struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	Challenge              string                 `json:"challenge"`
	PubKeyCredParams       []pubKeyCredParam      `json:"pubKeyCredParams"`
	ExcludeCredentials     []credentialDescriptor `json:"excludeCredentials"`
	AuthenticatorSelection struct {
		ResidentKey        string `json:"residentKey"`
		RequireResidentKey bool   `json:"requireResidentKey"`
		UserVerification   string `json:"userVerification"`
	} `json:"authenticatorSelection"`
	Attestation string `json:"attestation"`
	Extensions  struct {
		CredProps bool `json:"credProps"`
	} `json:"extensions"`
	Timeout int64 `json:"timeout"`
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
func (rp *RelyingParty) NewRegistration(user User, passkeys []string) (optionsJSON []byte, err error) {
	if len(user.ID) == 0 || len(user.ID) > 64 {
		return nil, errors.New("passkey: invalid user ID")
	}
	exclude, err := credentialDescriptors(passkeys)
	if err != nil {
		return nil, err
	}
	var o creationOptions
	o.RP.ID = rp.rpID
	o.User.ID = base64.RawURLEncoding.EncodeToString([]byte(user.ID))
	o.User.Name = user.Name
	o.User.DisplayName = user.Name
	o.Challenge = base64.RawURLEncoding.EncodeToString([]byte{0})
	o.PubKeyCredParams = supportedAlgorithms
	o.ExcludeCredentials = exclude
	o.AuthenticatorSelection.ResidentKey = "required"
	o.AuthenticatorSelection.RequireResidentKey = true
	if rp.requireUserVerification {
		o.AuthenticatorSelection.UserVerification = "required"
	} else {
		o.AuthenticatorSelection.UserVerification = "preferred"
	}
	o.Attestation = "none"
	o.Extensions.CredProps = true
	o.Timeout = rp.timeout.Milliseconds()
	return json.Marshal(o)
}

// registrationResponse is the RegistrationResponseJSON of WebAuthn L3 §5.8,
// as produced by PublicKeyCredential.toJSON().
type registrationResponse struct {
	Response struct {
		ClientDataJSON    string   `json:"clientDataJSON"`
		AuthenticatorData string   `json:"authenticatorData"`
		Transports        []string `json:"transports"`
	} `json:"response"`
	ClientExtensionResults struct {
		CredProps *struct {
			RK *bool `json:"rk"`
		} `json:"credProps"`
	} `json:"clientExtensionResults"`
}

// clientData is the subset of the client data JSON this package checks.
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin *bool  `json:"crossOrigin"`
}

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
func (rp *RelyingParty) Register(responseJSON []byte) (passkey string, err error) {
	var resp registrationResponse
	// TODO: use json/v2 to reject duplicates and match case-sensitive.
	if err := json.Unmarshal(responseJSON, &resp); err != nil {
		return "", fmt.Errorf("passkey: malformed registration response: %w", err)
	}

	cd, err := base64RawURLDecodeString(resp.Response.ClientDataJSON)
	if err != nil {
		return "", fmt.Errorf("passkey: malformed client data encoding: %w", err)
	}
	var c clientData
	if err := json.Unmarshal(cd, &c); err != nil {
		return "", fmt.Errorf("passkey: malformed client data JSON: %w", err)
	}
	if c.Type != "webauthn.create" {
		return "", fmt.Errorf("passkey: client data type is %q, expected %q", c.Type, "webauthn.create")
	}
	// For registration, we don't check the challenge, because we don't do
	// attestation and we don't keep state.
	_ = c.Challenge
	if c.Origin != rp.origin {
		return "", fmt.Errorf("passkey: client data origin %q is not the expected one", c.Origin)
	}
	if c.CrossOrigin != nil && *c.CrossOrigin {
		return "", errors.New("passkey: ceremony was performed in a cross-origin frame")
	}

	for _, t := range resp.Response.Transports {
		if !validTransport(t) {
			// Drop all transports if they can't be encoded.
			resp.Response.Transports = nil
			break
		}
	}
	slices.Sort(resp.Response.Transports)
	resp.Response.Transports = slices.Compact(resp.Response.Transports)

	ad, err := base64RawURLDecodeString(resp.Response.AuthenticatorData)
	if err != nil {
		return "", fmt.Errorf("passkey: malformed authenticator data encoding: %w", err)
	}
	r := &record{}
	if err := parseRegistrationAuthData(r, ad); err != nil {
		return "", fmt.Errorf("passkey: malformed authenticator data: %w", err)
	}
	if r.rpIDHash != sha256.Sum256([]byte(rp.rpID)) {
		return "", errors.New("passkey: registration for a different RP ID")
	}
	if r.flags&flagBE == 0 && r.flags&flagBS != 0 {
		return "", errors.New("passkey: credential is backed up but not backup eligible")
	}
	// credProps reports whether the created credential is actually
	// discoverable. Absence is accepted (Safari never reports it), but an
	// explicit false contradicts residentKey: "required".
	if cp := resp.ClientExtensionResults.CredProps; cp != nil && cp.RK != nil && !*cp.RK {
		return "", errors.New("passkey: client reports the credential is not discoverable")
	}

	return encodeRecord(ad, r.transports), nil
}

// validTransport reports whether t matches [a-z0-9-]+.
func validTransport(t string) bool {
	if t == "" {
		return false
	}
	for c := range t {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

func base64RawURLDecodeString(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("invalid base64 encoding")
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}
