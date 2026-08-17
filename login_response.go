package passkey

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Response is a parsed PublicKeyCredential returned by
// navigator.credentials.get().
//
// It is NOT verified until it is passed to [RelyingParty.Login] and Login
// succeeds. It is meant to be used for looking up the request and the user's
// passkey records.
type Response struct {
	credentialID []byte

	clientDataHash [32]byte
	challenge      [32]byte
	origin         string

	authData     []byte
	rpIDHash     [32]byte
	userVerified bool
	backedUp     bool

	signature []byte
	userID    string // empty for user-scoped ceremonies
}

// authenticationResponse is the AuthenticationResponseJSON of WebAuthn L3
// §5.1, as produced by PublicKeyCredential.toJSON().
type authenticationResponse struct {
	RawID    string `json:"rawId"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle"`
	} `json:"response"`
}

// ParseResponse parses a login response into a [Response].
//
// responseJSON is the JSON serialization of the PublicKeyCredential returned by
// navigator.credentials.get() (as produced by its toJSON() method).
//
// It does not verify the response: use [RelyingParty.Login] to verify it
// against the request and the user's passkey records.
func ParseResponse(responseJSON []byte) (*Response, error) {
	var r authenticationResponse
	if err := json.Unmarshal(responseJSON, &r); err != nil {
		return nil, fmt.Errorf("passkey: invalid response JSON: %w", err)
	}
	credID, err := base64RawURLDecodeString(r.RawID)
	if err != nil {
		return nil, fmt.Errorf("passkey: malformed credential ID: %w", err)
	}
	if len(credID) == 0 {
		return nil, errors.New("passkey: response has no credential ID")
	}

	cd, err := base64RawURLDecodeString(r.Response.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("passkey: malformed client data encoding: %w", err)
	}
	var c clientData
	if err := json.Unmarshal(cd, &c); err != nil {
		return nil, fmt.Errorf("passkey: malformed client data JSON: %w", err)
	}
	if c.Type != "webauthn.get" {
		return nil, fmt.Errorf("passkey: client data type is %q, expected %q", c.Type, "webauthn.get")
	}
	ch, err := base64RawURLDecodeString(c.Challenge)
	if err != nil {
		return nil, fmt.Errorf("passkey: malformed client data encoding: %w", err)
	}
	if len(ch) != 32 {
		return nil, fmt.Errorf("passkey: malformed challenge")
	}
	challenge := [32]byte(ch)
	if c.CrossOrigin != nil && *c.CrossOrigin {
		return nil, errors.New("passkey: ceremony was performed in a cross-origin frame")
	}
	if c.TopOrigin != nil {
		return nil, errors.New("passkey: ceremony was performed in a cross-origin frame")
	}

	ad, err := base64RawURLDecodeString(r.Response.AuthenticatorData)
	if err != nil {
		return nil, fmt.Errorf("passkey: malformed authenticator data encoding: %w", err)
	}
	if len(ad) < 32+1+4 {
		return nil, errors.New("passkey: malformed authenticator data")
	}
	rpIDHash := [32]byte(ad[:32])
	flags := flags(ad[32])
	if flags.attestedData() {
		return nil, errors.New("passkey: authenticator data unexpectedly has attested data")
	}
	if flags.extensionData() {
		if len(ad) == 32+1+4 {
			return nil, errors.New("passkey: authenticator data claims extension data but has none")
		}
	} else {
		if len(ad) != 32+1+4 {
			return nil, fmt.Errorf("passkey: authenticator data has %d unexpected trailing bytes",
				len(ad)-(32+1+4))
		}
	}
	if !flags.userPresent() {
		return nil, errors.New("passkey: user presence flag not set")
	}
	if flags.backupState() && !flags.backupEligible() {
		return nil, errors.New("passkey: credential is backed up but not backup eligible")
	}

	sig, err := base64RawURLDecodeString(r.Response.Signature)
	if err != nil {
		return nil, fmt.Errorf("passkey: malformed signature: %w", err)
	}

	u, err := base64RawURLDecodeString(r.Response.UserHandle)
	if err != nil {
		return nil, fmt.Errorf("passkey: malformed user ID: %w", err)
	}
	// We are supposed to reject present-but-empty user IDs, but apparently some
	// clients produce(d) them. https://github.com/w3c/webauthn/issues/1722
	if len(u) > 64 {
		return nil, errors.New("passkey: invalid user ID")
	}
	userID := string(u)
	if userScoped(challenge) {
		userID = ""
	} else if userID == "" {
		return nil, errors.New("passkey: assertion has no user handle")
	}

	return &Response{
		credentialID:   credID,
		clientDataHash: sha256.Sum256(cd),
		challenge:      challenge,
		origin:         c.Origin,
		authData:       ad,
		rpIDHash:       rpIDHash,
		userVerified:   flags.userVerified(),
		backedUp:       flags.backupState(),
		signature:      sig,
		userID:         userID,
	}, nil
}

// BackedUp reports whether the credential asserts it is currently backed up,
// according to the login response. It can be checked after a successful
// [RelyingParty.Login] to inform account recovery decisions.
func (r *Response) BackedUp() bool {
	return r.backedUp
}

// RequestID returns the unique identifier of the request this response
// is for, as returned by [RequestID] when the request was created. It can
// be used to look up the stored request.
func (r *Response) RequestID() string {
	h := hmac.New(sha256.New, []byte("crypto/passkey request ID"))
	h.Write(r.challenge[:])
	id := h.Sum(make([]byte, 0, 32))
	return base64.RawURLEncoding.EncodeToString(id)
}

// UnauthenticatedUserID returns the user ID asserted by this response.
//
// This user ID is attacker-controlled until the response is verified with
// [RelyingParty.Login], and must not be used for anything but looking up
// the user's passkey records.
//
// It is empty if and only if [RelyingParty.NewLoginWithCredentials] initiated
// the ceremony: the application identified the user before beginning the
// ceremony, and must look up their records the same way, not from the response.
func (r *Response) UnauthenticatedUserID() string {
	return r.userID
}

// UserVerified reports whether user verification was performed,
// according to a login response. It can be checked after a successful
// [RelyingParty.Login] to gate sensitive operations.
func (r *Response) UserVerified() bool {
	return r.userVerified
}
