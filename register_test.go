package passkey

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// regJSON returns a valid registration response for the test RP.
func regJSON(t *testing.T, a *authenticator, flags byte) []byte {
	t.Helper()
	return mustJSON(t, a.registrationResponse(t, testRPID, testOrigin, "AA", flags))
}

func authDataOf(t testing.TB, m map[string]any) []byte {
	t.Helper()
	encoded := m["response"].(map[string]any)["authenticatorData"].(string)
	ad, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return ad
}

func setAuthData(m map[string]any, ad []byte) map[string]any {
	m["response"].(map[string]any)["authenticatorData"] = base64.RawURLEncoding.EncodeToString(ad)
	return m
}

// TestRegister exercises each Register check: every case is a fully
// valid registration response except for the one check under test.
// Registration responses are not signed (attestation "none"), so no
// re-signing is involved.
func TestRegister(t *testing.T) {
	tests := []struct {
		name   string
		resp   func(t *testing.T, a *authenticator) []byte
		ok     bool
		errIs  error
		errHas string
	}{
		{
			name: "valid",
			resp: func(t *testing.T, a *authenticator) []byte {
				return regJSON(t, a, flagUP|flagUV)
			},
			ok: true,
		},
		{
			name: "invalid JSON",
			resp: func(t *testing.T, a *authenticator) []byte {
				return []byte("{")
			},
			errHas: "malformed registration response",
		},
		{
			name: "client data encoding",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := a.registrationResponse(t, testRPID, testOrigin, "AA", flagUP|flagUV)
				m["response"].(map[string]any)["clientDataJSON"] = "!!!"
				return mustJSON(t, m)
			},
			errHas: "malformed client data encoding",
		},
		{
			name: "client data JSON",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := a.registrationResponse(t, testRPID, testOrigin, "AA", flagUP|flagUV)
				notJSON := base64.RawURLEncoding.EncodeToString([]byte("not json"))
				m["response"].(map[string]any)["clientDataJSON"] = notJSON
				return mustJSON(t, m)
			},
			errHas: "malformed client data JSON",
		},
		{
			name: "client data type",
			resp: func(t *testing.T, a *authenticator) []byte {
				a.clientDataType = "webauthn.get"
				return regJSON(t, a, flagUP|flagUV)
			},
			errHas: `client data type is "webauthn.get"`,
		},
		{
			name: "wrong origin",
			resp: func(t *testing.T, a *authenticator) []byte {
				return mustJSON(t, a.registrationResponse(t, testRPID, "https://attacker.example", "AA", flagUP|flagUV))
			},
			errHas: "is not the expected one",
		},
		{
			name: "cross-origin",
			resp: func(t *testing.T, a *authenticator) []byte {
				crossOrigin := true
				a.crossOrigin = &crossOrigin
				return regJSON(t, a, flagUP|flagUV)
			},
			errHas: "cross-origin frame",
		},
		{
			name: "cross-origin absent",
			resp: func(t *testing.T, a *authenticator) []byte {
				a.crossOrigin = nil
				return regJSON(t, a, flagUP|flagUV)
			},
			ok: true,
		},
		{
			name: "top origin",
			resp: func(t *testing.T, a *authenticator) []byte {
				a.clientDataExtra = map[string]any{"topOrigin": testOrigin}
				return regJSON(t, a, flagUP|flagUV)
			},
			errHas: "cross-origin frame",
		},
		{
			// Register does not require UP or UV, to support conditional
			// (automatic) passkey creation.
			name: "no user presence or verification",
			resp: func(t *testing.T, a *authenticator) []byte {
				return regJSON(t, a, 0)
			},
			ok: true,
		},
		{
			name: "authenticator data encoding",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := a.registrationResponse(t, testRPID, testOrigin, "AA", flagUP|flagUV)
				m["response"].(map[string]any)["authenticatorData"] = "!!!"
				return mustJSON(t, m)
			},
			errHas: "malformed authenticator data encoding",
		},
		{
			name: "authenticator data too short",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := a.registrationResponse(t, testRPID, testOrigin, "AA", flagUP|flagUV)
				return mustJSON(t, setAuthData(m, make([]byte, 54)))
			},
			errHas: "expected at least 55",
		},
		{
			name: "authenticator data too long",
			resp: func(t *testing.T, a *authenticator) []byte {
				a.extensions = make([]byte, 8200)
				return regJSON(t, a, flagUP|flagUV)
			},
			errHas: "expected at most 8192",
		},
		{
			name: "no attested credential data",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := a.registrationResponse(t, testRPID, testOrigin, "AA", flagUP|flagUV)
				// Extension data pads the assertion-shaped authenticator
				// data past the 55-byte minimum, so that only the AT
				// flag check fails.
				a.extensions = make([]byte, 18)
				return mustJSON(t, setAuthData(m, a.authData(testRPID, false, flagUP|flagUV)))
			},
			errHas: "no attested credential data",
		},
		{
			name: "backup state without eligibility",
			resp: func(t *testing.T, a *authenticator) []byte {
				return regJSON(t, a, flagUP|flagBS)
			},
			errHas: "backed up but not backup eligible",
		},
		{
			name: "backup eligible and backed up",
			resp: func(t *testing.T, a *authenticator) []byte {
				return regJSON(t, a, flagUP|flagBE|flagBS)
			},
			ok: true,
		},
		{
			name: "credential ID too short",
			resp: func(t *testing.T, a *authenticator) []byte {
				a.credentialID = make([]byte, 15)
				return regJSON(t, a, flagUP|flagUV)
			},
			errHas: "credential ID is 15 bytes",
		},
		{
			name: "credential ID too long",
			resp: func(t *testing.T, a *authenticator) []byte {
				a.credentialID = make([]byte, 1024)
				return regJSON(t, a, flagUP|flagUV)
			},
			errHas: "credential ID is 1024 bytes",
		},
		{
			name: "credential ID lower bound",
			resp: func(t *testing.T, a *authenticator) []byte {
				a.credentialID = make([]byte, 16)
				return regJSON(t, a, flagUP|flagUV)
			},
			ok: true,
		},
		{
			name: "credential ID upper bound",
			resp: func(t *testing.T, a *authenticator) []byte {
				a.credentialID = make([]byte, 1023)
				return regJSON(t, a, flagUP|flagUV)
			},
			ok: true,
		},
		{
			name: "truncated credential ID",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := a.registrationResponse(t, testRPID, testOrigin, "AA", flagUP|flagUV)
				ad := authDataOf(t, m)
				return mustJSON(t, setAuthData(m, ad[:32+1+4+16+2+8]))
			},
			errHas: "too short for the credential ID",
		},
		{
			name: "malformed COSE key",
			resp: func(t *testing.T, a *authenticator) []byte {
				a.coseKey = []byte{0xff}
				return regJSON(t, a, flagUP|flagUV)
			},
			errHas: "bad map header",
		},
		{
			name: "unsupported COSE algorithm",
			resp: func(t *testing.T, a *authenticator) []byte {
				// An ES384 EC2 key: rejected at the alg check.
				key := cborAppendMapHeader(nil, 5)
				key = cborAppendInt(key, 1)
				key = cborAppendInt(key, coseKeyTypeEC2)
				key = cborAppendInt(key, 3)
				key = cborAppendInt(key, -35)
				a.coseKey = key
				return regJSON(t, a, flagUP|flagUV)
			},
			errIs:  ErrUnsupportedAlgorithm,
			errHas: "COSE algorithm -35",
		},
		{
			name: "ML-DSA-65 credential",
			resp: func(t *testing.T, a *authenticator) []byte {
				return regJSON(t, newAuthenticator(t, algMLDSA65), flagUP|flagUV)
			},
			errIs: ErrUnsupportedAlgorithm,
		},
		{
			name: "ML-DSA-87 credential",
			resp: func(t *testing.T, a *authenticator) []byte {
				return regJSON(t, newAuthenticator(t, algMLDSA87), flagUP|flagUV)
			},
			errIs: ErrUnsupportedAlgorithm,
		},
		{
			name: "extension data claimed but absent",
			resp: func(t *testing.T, a *authenticator) []byte {
				return regJSON(t, a, flagUP|flagUV|flagED)
			},
			errHas: "claims extension data but has none",
		},
		{
			name: "trailing bytes without extension flag",
			resp: func(t *testing.T, a *authenticator) []byte {
				a.extensions = []byte{0x01, 0x02, 0x03}
				m := a.registrationResponse(t, testRPID, testOrigin, "AA", flagUP|flagUV)
				ad := authDataOf(t, m)
				ad[32] &^= flagED
				return mustJSON(t, setAuthData(m, ad))
			},
			errHas: "3 unexpected trailing bytes",
		},
		{
			name: "extension data",
			resp: func(t *testing.T, a *authenticator) []byte {
				a.extensions = []byte{0xa0}
				return regJSON(t, a, flagUP|flagUV)
			},
			ok: true,
		},
		{
			name: "wrong RP ID",
			resp: func(t *testing.T, a *authenticator) []byte {
				return mustJSON(t, a.registrationResponse(t, "attacker.example", testOrigin, "AA", flagUP|flagUV))
			},
			errHas: "registration for a different RP ID",
		},
		{
			// The authenticator data is parsed before the RP ID hash is
			// compared, so a parse failure masks the RP ID check.
			name: "malformed authenticator data masks wrong RP ID",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := a.registrationResponse(t, "attacker.example", testOrigin, "AA", flagUP|flagUV)
				ad := authDataOf(t, m)
				return mustJSON(t, setAuthData(m, ad[:54]))
			},
			errHas: "expected at least 55",
		},
		{
			name: "credProps rk false",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := a.registrationResponse(t, testRPID, testOrigin, "AA", flagUP|flagUV)
				m["clientExtensionResults"] = map[string]any{"credProps": map[string]any{"rk": false}}
				return mustJSON(t, m)
			},
			errHas: "not discoverable",
		},
		{
			name: "credProps rk absent",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := a.registrationResponse(t, testRPID, testOrigin, "AA", flagUP|flagUV)
				m["clientExtensionResults"] = map[string]any{"credProps": map[string]any{}}
				return mustJSON(t, m)
			},
			ok: true,
		},
		{
			name: "credProps absent",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := a.registrationResponse(t, testRPID, testOrigin, "AA", flagUP|flagUV)
				m["clientExtensionResults"] = map[string]any{}
				return mustJSON(t, m)
			},
			ok: true,
		},
		{
			name: "clientExtensionResults absent",
			resp: func(t *testing.T, a *authenticator) []byte {
				m := a.registrationResponse(t, testRPID, testOrigin, "AA", flagUP|flagUV)
				delete(m, "clientExtensionResults")
				return mustJSON(t, m)
			},
			ok: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp := newTestRP(t, Options{})
			a := newAuthenticator(t, algES256)
			record, err := rp.Register(tt.resp(t, a))
			if tt.ok {
				if err != nil {
					t.Fatalf("Register() = %v, want success", err)
				}
				if _, err := parseRecord(record); err != nil {
					t.Errorf("parseRecord(Register()) = %v, want success", err)
				}
				return
			}
			checkError(t, err, tt.errIs, tt.errHas)
		})
	}
}

// TestValidTransport checks the transport grammar, the C2SP draft's
// [a-zA-Z0-9/.-]+, at most 32 bytes.
func TestValidTransport(t *testing.T) {
	valid := []string{
		"usb", "nfc", "ble", "internal", "hybrid", "smart-card",
		"a/b", "a.b", "A-B", "-a", "a-", "0", strings.Repeat("a", 32),
	}
	invalid := []string{
		"", "a+b", "a b", "usb,", "café", "a\nb", strings.Repeat("a", 33),
	}
	for _, tr := range valid {
		if !validTransport(tr) {
			t.Errorf("validTransport(%q) = false, want true", tr)
		}
	}
	for _, tr := range invalid {
		if validTransport(tr) {
			t.Errorf("validTransport(%q) = true, want false", tr)
		}
	}
}

// TestRegisterTransports checks how Register sanitizes the response
// transports into the record: any invalid entry drops the whole list
// (the C2SP draft's "MUST be omitted"), oversized lists are dropped,
// and valid lists are sorted and deduplicated.
func TestRegisterTransports(t *testing.T) {
	var many []string
	for i := range 33 {
		many = append(many, fmt.Sprintf("t%02d", i))
	}
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"duplicates", []string{"usb", "internal", "usb"}, []string{"internal", "usb"}},
		{"sorted", []string{"internal", "hybrid"}, []string{"hybrid", "internal"}},
		{"none", nil, nil},
		{"one invalid drops all", []string{"usb", "not valid!"}, nil},
		{"too many drop all", many, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp := newTestRP(t, Options{})
			a := newAuthenticator(t, algES256)
			a.transports = tt.in
			record, err := rp.Register(regJSON(t, a, flagUP|flagUV))
			if err != nil {
				t.Fatal(err)
			}
			transports, err := Transports(record)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(transports, tt.want) {
				t.Errorf("Transports() = %q, want %q", transports, tt.want)
			}
			if tt.want == nil {
				rest := strings.TrimPrefix(record, "$webauthn$v=1$")
				if strings.Contains(rest, "$") {
					t.Errorf("record %q has a parameters field, want none", record)
				}
			}
		})
	}
}

// TestNewRegistration checks the creation options production: user IDs
// are 1 to 64 arbitrary bytes, user names reject control and
// bidirectional formatting characters, and malformed records are
// dropped from excludeCredentials rather than failing the ceremony.
func TestNewRegistration(t *testing.T) {
	rp := newTestRP(t, Options{})
	valid := User{ID: "user-id", Name: "user@example.com"}

	creationJSON, err := rp.NewRegistration(valid, []string{"not a passkey record"})
	if err != nil {
		t.Fatalf("NewRegistration() with a malformed record = %v, want success", err)
	}
	if !strings.Contains(string(creationJSON), `"excludeCredentials":[]`) {
		t.Errorf("options = %s, want an empty excludeCredentials list", creationJSON)
	}

	if _, err := rp.NewRegistration(valid, nil); err != nil {
		t.Errorf("NewRegistration() = %v, want success", err)
	}
	if _, err := rp.NewRegistration(User{ID: "\x00\xff\x80", Name: "n"}, nil); err != nil {
		t.Errorf("NewRegistration() with an arbitrary-bytes user ID = %v, want success", err)
	}
	if _, err := rp.NewRegistration(User{ID: strings.Repeat("a", 64), Name: "n"}, nil); err != nil {
		t.Errorf("NewRegistration() with a 64-byte user ID = %v, want success", err)
	}
	if _, err := rp.NewRegistration(User{ID: "", Name: "n"}, nil); err == nil {
		t.Error("NewRegistration() with an empty user ID succeeded, want error")
	}
	if _, err := rp.NewRegistration(User{ID: strings.Repeat("a", 65), Name: "n"}, nil); err == nil {
		t.Error("NewRegistration() with a 65-byte user ID succeeded, want error")
	}
	if _, err := rp.NewRegistration(User{ID: "user-id", Name: "a\nb"}, nil); err == nil {
		t.Error("NewRegistration() with a control character in the name succeeded, want error")
	}
	if _, err := rp.NewRegistration(User{ID: "user-id", Name: "a\u202eb"}, nil); err == nil {
		t.Error("NewRegistration() with a bidi override in the name succeeded, want error")
	}
	if _, err := rp.NewRegistration(User{ID: "user-id", Name: "émoji 🎉"}, nil); err != nil {
		t.Errorf("NewRegistration() with a Unicode name = %v, want success", err)
	}
}
