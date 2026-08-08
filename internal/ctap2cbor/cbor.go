// Package ctap2cbor implements a tiny subset of CTAP2's subset of CBOR,
// sufficient to parse COSE keys and attestation objects.
//
// Only major types 0 (unsigned integer), 1 (negative integer), 2 (byte
// strings), and 5 (maps) are supported. Arguments are limited to 16-bit values.
//
// See https://www.imperialviolet.org/tourofwebauthn/tourofwebauthn.html#cbor.
package ctap2cbor

import (
	"encoding/binary"
	"math"
)

type String []byte

func (s String) Empty() bool {
	return len(s) == 0
}

func (s *String) readTypeAndArgument() (major uint8, arg uint16, ok bool) {
	if len(*s) < 1 {
		return
	}
	major = (*s)[0] >> 5
	minor := (*s)[0] & 0x1f
	switch {
	case minor <= 23:
		arg = uint16(minor)
		*s = (*s)[1:]
	case minor == 24:
		if len(*s) < 2 {
			return
		}
		arg = uint16((*s)[1])
		if arg <= 23 {
			return
		}
		*s = (*s)[2:]
	case minor == 25:
		if len(*s) < 3 {
			return
		}
		arg = binary.BigEndian.Uint16((*s)[1:])
		if arg <= 0xff {
			return
		}
		*s = (*s)[3:]
	default:
		return
	}
	ok = true
	return
}

func (s *String) ReadInt(out *int16) bool {
	major, arg, ok := s.readTypeAndArgument()
	if !ok {
		return false
	}
	switch major {
	case 0:
		if arg > math.MaxInt16 {
			return false
		}
		*out = int16(arg)
	case 1:
		if arg > -math.MinInt16-1 {
			return false
		}
		*out = -int16(arg) - 1
	default:
		return false
	}
	return true
}

func (s *String) ReadBytes(out *[]byte) bool {
	major, arg, ok := s.readTypeAndArgument()
	if !ok || major != 2 {
		return false
	}
	if len(*s) < int(arg) {
		return false
	}
	*out = (*s)[:arg]
	*s = (*s)[arg:]
	return true
}

func (s *String) ReadMapHeader(out *uint16) bool {
	major, arg, ok := s.readTypeAndArgument()
	if !ok || major != 5 {
		return false
	}
	*out = arg
	return true
}
