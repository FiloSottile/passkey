package passkey

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"time"
)

//	enum {
//	    unscoped(0),
//	    user_scoped(1),
//	    (255)
//	} CeremonyKind;
//
//	struct {
//	    CeremonyKind kind;
//	    opaque random[31];
//	} Challenge;
//
//	struct {
//	    uint8 version = 1;
//	    opaque challenge[32];
//	    uint64 creation_time;
//	} Request;
type loginRequest struct {
	challenge [32]byte
	created   time.Time
}

// The ceremony kind travels with the challenge, so it can be read from a
// response before its request is looked up.
const (
	// challengeUnscoped is a ceremony begun by [RelyingParty.NewLogin]: the
	// response identifies the user.
	challengeUnscoped = 0
	// challengeUserScoped is a ceremony begun by
	// [RelyingParty.NewLoginWithCredentials]: the application identified the
	// user, and the response's user handle is disregarded.
	challengeUserScoped = 1
)

func userScoped(challenge [32]byte) bool {
	return challenge[0] == challengeUserScoped
}

func newLoginRequest(scoped bool) *loginRequest {
	r := &loginRequest{}
	if scoped {
		r.challenge[0] = challengeUserScoped
	} else {
		r.challenge[0] = challengeUnscoped
	}
	rand.Read(r.challenge[1:])
	r.created = time.Now().Truncate(time.Second)
	return r
}

func parseLoginRequest(b []byte) (*loginRequest, error) {
	if len(b) == 0 {
		return nil, errors.New("passkey: invalid stored request")
	}
	if b[0] != 1 {
		return nil, errors.New("passkey: invalid stored request: unknown version")
	}
	if len(b) != 1+32+8 {
		return nil, errors.New("passkey: invalid stored request: invalid length")
	}
	r := &loginRequest{}
	copy(r.challenge[:], b[1:33])
	t := binary.BigEndian.Uint64(b[33:41])
	if t > math.MaxInt64 {
		return nil, errors.New("passkey: invalid stored request: invalid time")
	}
	r.created = time.Unix(int64(t), 0)
	return r, nil
}

func (r *loginRequest) Bytes() []byte {
	b := make([]byte, 0, 1+32+8)
	b = append(b, 1)
	b = append(b, r.challenge[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(r.created.Unix()))
	return b
}

// RequestCreation returns the creation time of a request returned by
// [RelyingParty.NewLogin] or [RelyingParty.NewLoginWithCredentials].
//
// A request expires [Options.Timeout] after creation.
//
// If the request is invalid, RequestCreation returns the zero [time.Time].
func RequestCreation(request []byte) time.Time {
	r, err := parseLoginRequest(request)
	if err != nil {
		return time.Time{}
	}
	return r.created
}

// RequestID returns a unique identifier for a request returned by
// [RelyingParty.NewLogin] or [RelyingParty.NewLoginWithCredentials], to be used
// as a storage key. The same value is returned by [Response.RequestID]
// for the corresponding response.
//
// If the request is invalid, RequestID returns an empty string.
func RequestID(request []byte) string {
	r, err := parseLoginRequest(request)
	if err != nil {
		return ""
	}
	h := hmac.New(sha256.New, []byte("crypto/passkey request ID"))
	h.Write(r.challenge[:])
	id := h.Sum(make([]byte, 0, 32))
	return base64.RawURLEncoding.EncodeToString(id)
}
