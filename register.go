package passkey

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"filippo.io/passkey/internal/ctap2cbor"
)

// User identifies the account a passkey is being registered for.
type User struct {
	// ID is the opaque user ID; see [User IDs].
	//
	// [User IDs]: #hdr-User_IDs
	ID string

	// Name is a human-readable identifier for the account, such as a
	// username or email address. It must not be empty. It is displayed in
	// credential pickers and stored by the authenticator, but never
	// returned to the server or used in the protocol.
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
//
//  1. parsed from JSON on the client side, then
//  2. passed to PublicKeyCredential.parseCreationOptionsFromJSON(), and then
//  3. passed to navigator.credentials.create() as the publicKey field.
//
// It can be used both for modal and for conditional UI flows.
//
// Registration is stateless for the server: there is no request value
// to store, and the response is verified by [RelyingParty.Register].
func (rp *RelyingParty) NewRegistration(user User, passkeys []string) (optionsJSON []byte, err error) {
	if len(user.ID) == 0 || len(user.ID) > 64 {
		return nil, errors.New("passkey: invalid user ID")
	}
	if user.Name == "" {
		return nil, errors.New("passkey: user name is empty")
	}
	if strings.ContainsFunc(user.Name, disallowedNameRune) {
		return nil, errors.New("passkey: user name contains disallowed characters")
	}
	exclude := credentialDescriptors(passkeys)
	var o creationOptions
	o.RP.ID = rp.rpID
	o.RP.Name = rp.rpID
	o.User.ID = base64.RawURLEncoding.EncodeToString([]byte(user.ID))
	o.User.Name = user.Name
	o.User.DisplayName = user.Name
	o.Challenge = base64.RawURLEncoding.EncodeToString([]byte{0})
	o.PubKeyCredParams = supportedAlgorithms
	o.ExcludeCredentials = exclude
	o.AuthenticatorSelection.ResidentKey = "required"
	o.AuthenticatorSelection.RequireResidentKey = true
	// Always "preferred" to allow conditional registration.
	// See [RelyingParty.Login] and the "User verification" section.
	o.AuthenticatorSelection.UserVerification = "preferred"
	o.Attestation = "none"
	o.Extensions.CredProps = true
	o.Timeout = rp.timeout.Milliseconds()
	return json.Marshal(o)
}

// registrationResponse is the RegistrationResponseJSON of WebAuthn L3 §5.1,
// as produced by PublicKeyCredential.toJSON().
type registrationResponse struct {
	Response struct {
		ClientDataJSON    string   `json:"clientDataJSON"`
		AuthenticatorData string   `json:"authenticatorData"`
		AttestationObject string   `json:"attestationObject"`
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
	Type        string  `json:"type"`
	Challenge   string  `json:"challenge"`
	Origin      string  `json:"origin"`
	CrossOrigin *bool   `json:"crossOrigin"`
	TopOrigin   *string `json:"topOrigin"`
}

// Register verifies a registration response and, on success, returns
// the new passkey record, to be stored for the signed-in user whose
// session initiated the registration.
//
// responseJSON is the JSON serialization of the PublicKeyCredential
// returned by navigator.credentials.create() (as produced by its
// toJSON() method).
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
	// topOrigin is only present for a ceremony performed in a cross-origin
	// frame, which this package does not accept.
	if c.TopOrigin != nil {
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
	if len(resp.Response.Transports) > 32 {
		// Drop all transports if there are too many to store.
		resp.Response.Transports = nil
	}

	ad, err := base64RawURLDecodeString(resp.Response.AuthenticatorData)
	if err != nil {
		return "", fmt.Errorf("passkey: malformed authenticator data encoding: %w", err)
	}
	if len(ad) == 0 {
		// Browser APIs include authenticatorData, but some native platform APIs
		// expose only the attestation object.
		ao, err := base64RawURLDecodeString(resp.Response.AttestationObject)
		if err != nil {
			return "", fmt.Errorf("passkey: malformed attestation object encoding: %w", err)
		}
		if len(ao) == 0 {
			return "", errors.New("passkey: response has neither authenticatorData nor attestationObject")
		}
		if ad, err = parseAttestationObject(ao); err != nil {
			return "", fmt.Errorf("passkey: malformed attestation object: %w", err)
		}
	}
	r := &record{}
	if err := parseRegistrationAuthData(r, ad); err != nil {
		return "", fmt.Errorf("passkey: malformed authenticator data: %w", err)
	}
	if r.rpIDHash != sha256.Sum256([]byte(rp.rpID)) {
		return "", errors.New("passkey: registration for a different RP ID")
	}
	// credProps reports whether the created credential is actually
	// discoverable. Absence is accepted (Safari never reports it), but an
	// explicit false contradicts residentKey: "required".
	if cp := resp.ClientExtensionResults.CredProps; cp != nil && cp.RK != nil && !*cp.RK {
		return "", errors.New("passkey: client reports the credential is not discoverable")
	}
	// A record with neither UV nor BE would fail to log in.
	// See [RelyingParty.Login] and the "User verification" section.
	if !rp.optionalUserVerification && !r.flags.userVerified() && !r.flags.backupEligible() {
		return "", fmt.Errorf("%w: response has neither the UV nor the BE flag "+
			"(likely to be a security key without PIN)", ErrUserVerificationUnavailable)
	}

	return encodeRecord(ad, resp.Response.Transports), nil
}

// disallowedNameRune reports whether r may not appear in a [User.Name]: control
// characters and bidirectional formatting characters. See RFC 8265 and RFC 8266.
func disallowedNameRune(r rune) bool {
	return unicode.IsControl(r) ||
		(r >= 0x202A && r <= 0x202E) || // LRE, RLE, PDF, LRO, RLO
		(r >= 0x2066 && r <= 0x2069) // LRI, RLI, FSI, PDI
}

// validTransport reports whether t matches [a-zA-Z0-9/.-]+ and is at most 32 bytes.
func validTransport(t string) bool {
	if t == "" || len(t) > 32 {
		return false
	}
	for _, c := range t {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '/':
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

// parseAttestationObject returns the authData member of a CBOR attestation
// object. The attestation statement is not verified, and is skipped like any
// other member.
func parseAttestationObject(b []byte) ([]byte, error) {
	s := ctap2cbor.String(b)
	var pairs uint16
	if !s.ReadMapHeader(&pairs) {
		return nil, errors.New("bad map header")
	}
	var authData []byte
	var found bool
	for range pairs {
		var key string
		if !s.ReadString(&key) {
			return nil, errors.New("bad map key")
		}
		if key != "authData" {
			if !s.Skip() {
				return nil, fmt.Errorf("bad %q value", key)
			}
			continue
		}
		if found {
			return nil, errors.New("duplicate authData")
		}
		if !s.ReadBytes(&authData) {
			return nil, errors.New("bad authData")
		}
		found = true
	}
	if !found {
		return nil, errors.New("no authData")
	}
	if len(s) != 0 {
		return nil, fmt.Errorf("%d unexpected trailing bytes", len(s))
	}
	return authData, nil
}
