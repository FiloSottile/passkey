package passkey

import (
	"slices"
	"strings"
	"testing"
)

// TestLoginRequestRoundTrip checks that requests round-trip through
// Bytes and parseLoginRequest for empty and non-empty user IDs.
func TestLoginRequestRoundTrip(t *testing.T) {
	for _, userID := range []string{
		"",
		"u",
		"wxJph3ZClFxTP2xF9r2W0A",
		"\x00\xff\x80 arbitrary bytes",
		strings.Repeat("x", 64),
	} {
		r := newLoginRequest(userID)
		b := r.Bytes()
		if want := 42 + len(userID); len(b) != want {
			t.Errorf("Bytes() is %d bytes, want %d", len(b), want)
		}
		r2, err := parseLoginRequest(b)
		if err != nil {
			t.Fatalf("parseLoginRequest(%q) = %v", userID, err)
		}
		if r2.challenge != r.challenge {
			t.Errorf("challenge did not round-trip")
		}
		if r2.userID != userID {
			t.Errorf("userID = %q, want %q", r2.userID, userID)
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
	valid := newLoginRequest("user").Bytes()
	badVersion := slices.Clone(valid)
	badVersion[0] = 2
	tests := []struct {
		name    string
		request []byte
	}{
		{"empty", nil},
		{"too short", valid[:41]},
		{"unknown version", badVersion},
		{"trailing data", append(slices.Clone(valid), 'x')},
		{"truncated user ID", valid[:len(valid)-1]},
		{"oversized user ID", newLoginRequest(strings.Repeat("x", 65)).Bytes()},
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
