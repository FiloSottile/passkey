package passkey

import (
	"slices"
	"testing"
)

// TestLoginRequestRoundTrip checks that requests round-trip through
// Bytes and parseLoginRequest, keeping the challenge and the ceremony
// kind it carries, for both kinds of ceremony.
func TestLoginRequestRoundTrip(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		r := newLoginRequest(scoped)
		if userScoped(r.challenge) != scoped {
			t.Errorf("userScoped() = %v, want %v", userScoped(r.challenge), scoped)
		}
		b := r.Bytes()
		if len(b) != 41 {
			t.Errorf("Bytes() is %d bytes, want 41", len(b))
		}
		r2, err := parseLoginRequest(b)
		if err != nil {
			t.Fatalf("parseLoginRequest(scoped=%v) = %v", scoped, err)
		}
		if r2.challenge != r.challenge {
			t.Errorf("challenge did not round-trip")
		}
		if !r2.created.Equal(r.created) {
			t.Errorf("created = %v, want %v", r2.created, r.created)
		}
		if RequestID(b) == "" {
			t.Error("RequestID() is empty")
		}
		if RequestID(b) != RequestID(r.Bytes()) {
			t.Error("RequestID() is not deterministic")
		}
		if RequestCreation(b).IsZero() {
			t.Error("RequestCreation() is zero")
		}
	}
}

func TestParseLoginRequestInvalid(t *testing.T) {
	valid := newLoginRequest(false).Bytes()
	badVersion := slices.Clone(valid)
	badVersion[0] = 2
	tests := []struct {
		name    string
		request []byte
	}{
		{"empty", nil},
		{"too short", valid[:len(valid)-1]},
		{"unknown version", badVersion},
		{"trailing data", append(slices.Clone(valid), 'x')},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseLoginRequest(tt.request); err == nil {
				t.Error("parseLoginRequest() succeeded, want error")
			}
			if id := RequestID(tt.request); id != "" {
				t.Errorf("RequestID() = %q, want empty", id)
			}
			if created := RequestCreation(tt.request); !created.IsZero() {
				t.Errorf("RequestCreation() = %v, want zero", created)
			}
		})
	}
}
