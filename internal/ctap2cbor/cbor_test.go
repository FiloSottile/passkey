package ctap2cbor

import (
	"bytes"
	"testing"
)

// TestReadInt checks that integer arguments parse only from their
// single minimal-length encoding, only within the int16 range, and
// only for the integer major types.
func TestReadInt(t *testing.T) {
	valid := []struct {
		in   []byte
		want int16
	}{
		{[]byte{0x00}, 0},
		{[]byte{0x17}, 23},
		{[]byte{0x18, 0x18}, 24},
		{[]byte{0x18, 0xff}, 255},
		{[]byte{0x19, 0x01, 0x00}, 256},
		{[]byte{0x19, 0x7f, 0xff}, 32767},
		{[]byte{0x20}, -1},
		{[]byte{0x26}, -7},
		{[]byte{0x38, 0x18}, -25},
		{[]byte{0x38, 0x2f}, -48},
		{[]byte{0x39, 0x01, 0x00}, -257},
		{[]byte{0x39, 0x7f, 0xff}, -32768},
	}
	for _, tt := range valid {
		s := String(tt.in)
		var v int16
		if !s.ReadInt(&v) {
			t.Errorf("ReadInt(%x) failed, want %d", tt.in, tt.want)
			continue
		}
		if v != tt.want {
			t.Errorf("ReadInt(%x) = %d, want %d", tt.in, v, tt.want)
		}
		if len(s) != 0 {
			t.Errorf("ReadInt(%x) left %d bytes", tt.in, len(s))
		}
	}

	invalid := [][]byte{
		{0x38, 0x06},                   // -7 in non-minimal form (canonical: 26)
		{0x18, 0x00},                   // 0 in non-minimal form
		{0x18, 0x17},                   // 23 in non-minimal form
		{0x19, 0x00, 0xff},             // 255 with a two-byte argument
		{0x19, 0x80, 0x00},             // 32768 overflows int16
		{0x39, 0x80, 0x00},             // -32769 underflows int16
		{0x1a, 0x00, 0x00, 0x00, 0x07}, // 32-bit argument
		{0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07}, // 64-bit argument
		{0x1c},             // reserved minor
		{0x1f},             // indefinite length
		{0x18},             // truncated argument
		{0x19, 0x01},       // truncated argument
		{},                 // empty
		{0x40},             // byte string
		{0x60},             // text string
		{0x80},             // array
		{0xa0},             // map
		{0xc2, 0x00},       // tag
		{0xf9, 0x3c, 0x00}, // float16
		{0xf5},             // true
	}
	for _, in := range invalid {
		s := String(in)
		var v int16
		if s.ReadInt(&v) {
			t.Errorf("ReadInt(%x) = %d, want failure", in, v)
		}
	}
}

func TestReadBytes(t *testing.T) {
	valid := []struct {
		in   []byte
		want []byte
	}{
		{[]byte{0x40}, []byte{}},
		{[]byte{0x43, 0x01, 0x02, 0x03}, []byte{0x01, 0x02, 0x03}},
		{append([]byte{0x58, 0x18}, make([]byte, 24)...), make([]byte, 24)},
		{append([]byte{0x59, 0x01, 0x00}, make([]byte, 256)...), make([]byte, 256)},
	}
	for _, tt := range valid {
		s := String(tt.in)
		var v []byte
		if !s.ReadBytes(&v) {
			t.Errorf("ReadBytes(%x...) failed", tt.in[:min(4, len(tt.in))])
			continue
		}
		if !bytes.Equal(v, tt.want) {
			t.Errorf("ReadBytes(%x...) = %x, want %x", tt.in[:min(4, len(tt.in))], v, tt.want)
		}
		if len(s) != 0 {
			t.Errorf("ReadBytes(%x...) left %d bytes", tt.in[:min(4, len(tt.in))], len(s))
		}
	}

	invalid := [][]byte{
		{0x58, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}, // 5-byte length in non-minimal form
		{0x59, 0x00, 0x20},                         // 32-byte length in non-minimal form
		{0x43, 0x01, 0x02},                         // truncated payload
		{0x58, 0x18},                               // truncated payload
		{0x5f},                                     // indefinite length
		{0x05},                                     // unsigned integer
		{0x63, 0x61, 0x62, 0x63},                   // text string
	}
	for _, in := range invalid {
		s := String(in)
		var v []byte
		if s.ReadBytes(&v) {
			t.Errorf("ReadBytes(%x) = %x, want failure", in, v)
		}
	}
}

func TestReadMapHeader(t *testing.T) {
	valid := []struct {
		in   []byte
		want uint16
	}{
		{[]byte{0xa0}, 0},
		{[]byte{0xa5}, 5},
		{[]byte{0xb8, 0x18}, 24},
	}
	for _, tt := range valid {
		s := String(tt.in)
		var v uint16
		if !s.ReadMapHeader(&v) {
			t.Errorf("ReadMapHeader(%x) failed, want %d", tt.in, tt.want)
			continue
		}
		if v != tt.want {
			t.Errorf("ReadMapHeader(%x) = %d, want %d", tt.in, v, tt.want)
		}
	}

	invalid := [][]byte{
		{0xb8, 0x05},       // 5 pairs in non-minimal form
		{0xb9, 0x00, 0x18}, // 24 pairs in non-minimal form
		{0x85},             // array
		{0xbf},             // indefinite length
		{0xb8},             // truncated argument
	}
	for _, in := range invalid {
		s := String(in)
		var v uint16
		if s.ReadMapHeader(&v) {
			t.Errorf("ReadMapHeader(%x) = %d, want failure", in, v)
		}
	}
}
