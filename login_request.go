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

//	struct {
//	    uint8 version = 1;
//	    opaque challenge[32];
//	    uint64 creation_time;
//	    opaque user_id<0..64>;
//	} Request;
type loginRequest struct {
	challenge [32]byte
	created   time.Time
	userID    string // may be empty
}

func newLoginRequest(userID string) *loginRequest {
	r := &loginRequest{}
	rand.Read(r.challenge[:])
	r.created = time.Now().Truncate(time.Second)
	r.userID = userID
	return r
}

func parseLoginRequest(b []byte) (*loginRequest, error) {
	r := &loginRequest{}
	if len(b) < 1+32+8+1 {
		return nil, errors.New("passkey: invalid stored request")
	}
	v := b[0]
	b = b[1:]
	if v != 1 {
		return nil, errors.New("passkey: invalid stored request: unknown version")
	}
	copy(r.challenge[:], b[:32])
	b = b[32:]
	t := binary.BigEndian.Uint64(b)
	b = b[8:]
	if t > math.MaxInt64 {
		return nil, errors.New("passkey: invalid stored request: invalid time")
	}
	r.created = time.Unix(int64(t), 0)
	l := int(b[0])
	b = b[1:]
	if l != len(b) || l > 64 {
		return nil, errors.New("passkey: invalid stored request: invalid length")
	}
	r.userID = string(b)
	return r, nil
}

func (r *loginRequest) Bytes() []byte {
	b := make([]byte, 0, 1+32+8+1+len(r.userID))
	b = append(b, 1)
	b = append(b, r.challenge[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(r.created.Unix()))
	b = append(b, byte(len(r.userID)))
	b = append(b, r.userID...)
	return b
}

// RequestCreation returns the creation time of a request returned by
// [RelyingParty.NewLogin] or [RelyingParty.NewLoginForUser].
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
// [RelyingParty.NewLogin] or [RelyingParty.NewLoginForUser], to be used
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
