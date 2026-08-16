package ctap2cbor

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
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

// The CBOR major types, as assigned by RFC 8949, Section 3.1.
const (
	majorUint = iota
	majorNegative
	majorBytes
	majorText
	majorArray
	majorMap
	majorTag
	majorSimple
)

// cborExample is a row of Table 6 in RFC 8949, Appendix A: a CBOR data
// item in diagnostic notation and its hexadecimal encoding, annotated
// with the major type of the item, whether the encoding uses an
// indefinite length, and, for maps, the number of key/value pairs.
//
// For major types 0 and 1 the diagnostic notation is the decimal value
// of the integer, and for major type 2 it is the byte string content in
// hexadecimal.
type cborExample struct {
	diagnostic string
	encoded    string
	major      int
	indefinite bool
	pairs      int
}

func TestReadString(t *testing.T) {
	valid := []struct {
		in   []byte
		want string
	}{
		{[]byte{0x60}, ""},
		{[]byte{0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a'}, "authData"},
		{append([]byte{0x78, 0x18}, bytes.Repeat([]byte{'a'}, 24)...), strings.Repeat("a", 24)},
		{append([]byte{0x79, 0x01, 0x00}, bytes.Repeat([]byte{'a'}, 256)...), strings.Repeat("a", 256)},
	}
	for _, tt := range valid {
		s := String(tt.in)
		var v string
		if !s.ReadString(&v) {
			t.Errorf("ReadString(%x...) failed", tt.in[:min(4, len(tt.in))])
			continue
		}
		if v != tt.want {
			t.Errorf("ReadString(%x...) = %q, want %q", tt.in[:min(4, len(tt.in))], v, tt.want)
		}
		if len(s) != 0 {
			t.Errorf("ReadString(%x...) left %d bytes", tt.in[:min(4, len(tt.in))], len(s))
		}
	}

	invalid := [][]byte{
		{0x78, 0x03, 'a', 'b', 'c'}, // 3-byte length in non-minimal form
		{0x79, 0x00, 0x18},          // 24-byte length in non-minimal form
		{0x63, 'a', 'b'},            // truncated payload
		{0x7f},                      // indefinite length
		{0x05},                      // unsigned integer
		{0x43, 0x01, 0x02, 0x03},    // byte string
	}
	for _, in := range invalid {
		s := String(in)
		var v string
		if s.ReadString(&v) {
			t.Errorf("ReadString(%x) = %q, want failure", in, v)
		}
	}
}

func TestSkip(t *testing.T) {
	valid := []string{
		"00",                         // 0
		"3903e7",                     // -1000
		"40",                         // h''
		"4401020304",                 // h'01020304'
		"60",                         // ""
		"6449455446",                 // "IETF"
		"80",                         // []
		"83010203",                   // [1, 2, 3]
		"8301820203820405",           // [1, [2, 3], [4, 5]]
		"a0",                         // {}
		"a201020304",                 // {1: 2, 3: 4}
		"a26161016162820203",         // {"a": 1, "b": [2, 3]}
		"826161a161626163",           // ["a", {"b": "c"}]
		"a1636b65798181818181818100", // eight nested levels
	}
	for _, in := range valid {
		encoded, err := hex.DecodeString(in)
		if err != nil {
			t.Fatal(err)
		}
		// Trailing bytes are left behind.
		s := String(append(encoded, 0xff))
		if !s.Skip() {
			t.Errorf("Skip(%s) failed", in)
			continue
		}
		if len(s) != 1 {
			t.Errorf("Skip(%s) left %d bytes, want 1", in, len(s))
		}
	}

	invalid := []string{
		"",                             // empty
		"1a000f4240",                   // 1000000, in a 32-bit argument
		"5f42010243030405ff",           // (_ h'0102', h'030405')
		"9fff",                         // [_ ]
		"83018202039f0405ff",           // [1, [2, 3], [_ 4, 5]]
		"c11a514b67b0",                 // 1(1363896240)
		"f4",                           // false
		"f90000",                       // 0.0
		"1805",                         // 5, in a non-minimal argument
		"8301",                         // truncated array
		"a1636b6579",                   // truncated map
		"a1636b6579818181818181818100", // nine nested levels
	}
	for _, in := range invalid {
		encoded, err := hex.DecodeString(in)
		if err != nil {
			t.Fatal(err)
		}
		s := String(encoded)
		if s.Skip() {
			t.Errorf("Skip(%s) succeeded, want failure", in)
		}
	}
}

// TestRFC8949AppendixA runs every CBOR example published in RFC 8949,
// Appendix A through the accessors. The CTAP2 subset accepts only
// definite-length major types 0, 1, 2, 3, and 5, so most of the table must
// be rejected.
func TestRFC8949AppendixA(t *testing.T) {
	for _, tt := range rfc8949Examples {
		encoded, err := hex.DecodeString(tt.encoded)
		if err != nil {
			t.Fatalf("%s: %v", tt.diagnostic, err)
		}

		// ReadInt accepts the two integer major types when the value
		// fits in an int16. Arguments are limited to 16 bits as well,
		// but no example encodes a value in a wider argument than it
		// needs, so the range of the value alone decides.
		value, rangeErr := strconv.ParseInt(tt.diagnostic, 10, 16)
		wantInt := (tt.major == majorUint || tt.major == majorNegative) && rangeErr == nil

		s := String(encoded)
		var gotInt int16
		if ok := s.ReadInt(&gotInt); ok != wantInt {
			t.Errorf("%s: ReadInt(%s) = %v, want %v", tt.diagnostic, tt.encoded, ok, wantInt)
		} else if ok {
			if int64(gotInt) != value {
				t.Errorf("%s: ReadInt(%s) = %d, want %d", tt.diagnostic, tt.encoded, gotInt, value)
			}
			if len(s) != 0 {
				t.Errorf("%s: ReadInt(%s) left %d bytes", tt.diagnostic, tt.encoded, len(s))
			}
		}

		wantBytes := tt.major == majorBytes && !tt.indefinite
		s = String(encoded)
		var gotBytes []byte
		if ok := s.ReadBytes(&gotBytes); ok != wantBytes {
			t.Errorf("%s: ReadBytes(%s) = %v, want %v", tt.diagnostic, tt.encoded, ok, wantBytes)
		} else if ok {
			want := strings.TrimSuffix(strings.TrimPrefix(tt.diagnostic, "h'"), "'")
			if got := hex.EncodeToString(gotBytes); got != want {
				t.Errorf("%s: ReadBytes(%s) = %s, want %s", tt.diagnostic, tt.encoded, got, want)
			}
			if len(s) != 0 {
				t.Errorf("%s: ReadBytes(%s) left %d bytes", tt.diagnostic, tt.encoded, len(s))
			}
		}

		wantString := tt.major == majorText && !tt.indefinite
		s = String(encoded)
		var gotString string
		if ok := s.ReadString(&gotString); ok != wantString {
			t.Errorf("%s: ReadString(%s) = %v, want %v", tt.diagnostic, tt.encoded, ok, wantString)
		} else if ok {
			// The diagnostic notation of text strings is JSON.
			var want string
			if err := json.Unmarshal([]byte(tt.diagnostic), &want); err != nil {
				t.Fatalf("%s: %v", tt.diagnostic, err)
			}
			if gotString != want {
				t.Errorf("%s: ReadString(%s) = %q, want %q", tt.diagnostic, tt.encoded, gotString, want)
			}
			if len(s) != 0 {
				t.Errorf("%s: ReadString(%s) left %d bytes", tt.diagnostic, tt.encoded, len(s))
			}
		}

		wantMap := tt.major == majorMap && !tt.indefinite
		s = String(encoded)
		var gotPairs uint16
		if ok := s.ReadMapHeader(&gotPairs); ok != wantMap {
			t.Errorf("%s: ReadMapHeader(%s) = %v, want %v", tt.diagnostic, tt.encoded, ok, wantMap)
		} else if ok {
			if int(gotPairs) != tt.pairs {
				t.Errorf("%s: ReadMapHeader(%s) = %d, want %d", tt.diagnostic, tt.encoded, gotPairs, tt.pairs)
			}
			// The header of a map of at most 23 pairs is a single byte,
			// and the pairs themselves must be left behind.
			if tt.pairs <= 23 && len(s) != len(encoded)-1 {
				t.Errorf("%s: ReadMapHeader(%s) left %d bytes, want %d",
					tt.diagnostic, tt.encoded, len(s), len(encoded)-1)
			}
		}
	}
}

// rfc8949Examples is Table 6 of RFC 8949, Appendix A, in its published
// order, from https://www.rfc-editor.org/rfc/rfc8949.html#name-examples-of-encoded-cbor-da.
var rfc8949Examples = []cborExample{
	{"0", "00", majorUint, false, 0},
	{"1", "01", majorUint, false, 0},
	{"10", "0a", majorUint, false, 0},
	{"23", "17", majorUint, false, 0},
	{"24", "1818", majorUint, false, 0},
	{"25", "1819", majorUint, false, 0},
	{"100", "1864", majorUint, false, 0},
	{"1000", "1903e8", majorUint, false, 0},
	{"1000000", "1a000f4240", majorUint, false, 0},
	{"1000000000000", "1b000000e8d4a51000", majorUint, false, 0},
	{"18446744073709551615", "1bffffffffffffffff", majorUint, false, 0},
	{"18446744073709551616", "c249010000000000000000", majorTag, false, 0},
	{"-18446744073709551616", "3bffffffffffffffff", majorNegative, false, 0},
	{"-18446744073709551617", "c349010000000000000000", majorTag, false, 0},
	{"-1", "20", majorNegative, false, 0},
	{"-10", "29", majorNegative, false, 0},
	{"-100", "3863", majorNegative, false, 0},
	{"-1000", "3903e7", majorNegative, false, 0},
	{"0.0", "f90000", majorSimple, false, 0},
	{"-0.0", "f98000", majorSimple, false, 0},
	{"1.0", "f93c00", majorSimple, false, 0},
	{"1.1", "fb3ff199999999999a", majorSimple, false, 0},
	{"1.5", "f93e00", majorSimple, false, 0},
	{"65504.0", "f97bff", majorSimple, false, 0},
	{"100000.0", "fa47c35000", majorSimple, false, 0},
	{"3.4028234663852886e+38", "fa7f7fffff", majorSimple, false, 0},
	{"1.0e+300", "fb7e37e43c8800759c", majorSimple, false, 0},
	{"5.960464477539063e-8", "f90001", majorSimple, false, 0},
	{"0.00006103515625", "f90400", majorSimple, false, 0},
	{"-4.0", "f9c400", majorSimple, false, 0},
	{"-4.1", "fbc010666666666666", majorSimple, false, 0},
	{"Infinity", "f97c00", majorSimple, false, 0},
	{"NaN", "f97e00", majorSimple, false, 0},
	{"-Infinity", "f9fc00", majorSimple, false, 0},
	{"Infinity", "fa7f800000", majorSimple, false, 0},
	{"NaN", "fa7fc00000", majorSimple, false, 0},
	{"-Infinity", "faff800000", majorSimple, false, 0},
	{"Infinity", "fb7ff0000000000000", majorSimple, false, 0},
	{"NaN", "fb7ff8000000000000", majorSimple, false, 0},
	{"-Infinity", "fbfff0000000000000", majorSimple, false, 0},
	{"false", "f4", majorSimple, false, 0},
	{"true", "f5", majorSimple, false, 0},
	{"null", "f6", majorSimple, false, 0},
	{"undefined", "f7", majorSimple, false, 0},
	{"simple(16)", "f0", majorSimple, false, 0},
	{"simple(255)", "f8ff", majorSimple, false, 0},
	{"0(\"2013-03-21T20:04:00Z\")", "c074323031332d30332d32315432303a30343a30305a", majorTag, false, 0},
	{"1(1363896240)", "c11a514b67b0", majorTag, false, 0},
	{"1(1363896240.5)", "c1fb41d452d9ec200000", majorTag, false, 0},
	{"23(h'01020304')", "d74401020304", majorTag, false, 0},
	{"24(h'6449455446')", "d818456449455446", majorTag, false, 0},
	{"32(\"http://www.example.com\")", "d82076687474703a2f2f7777772e6578616d706c652e636f6d", majorTag, false, 0},
	{"h''", "40", majorBytes, false, 0},
	{"h'01020304'", "4401020304", majorBytes, false, 0},
	{"\"\"", "60", majorText, false, 0},
	{"\"a\"", "6161", majorText, false, 0},
	{"\"IETF\"", "6449455446", majorText, false, 0},
	{"\"\\\"\\\\\"", "62225c", majorText, false, 0},
	{"\"\\u00fc\"", "62c3bc", majorText, false, 0},
	{"\"\\u6c34\"", "63e6b0b4", majorText, false, 0},
	{"\"\\ud800\\udd51\"", "64f0908591", majorText, false, 0},
	{"[]", "80", majorArray, false, 0},
	{"[1, 2, 3]", "83010203", majorArray, false, 0},
	{"[1, [2, 3], [4, 5]]", "8301820203820405", majorArray, false, 0},
	{"[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]", "98190102030405060708090a0b0c0d0e0f101112131415161718181819", majorArray, false, 0},
	{"{}", "a0", majorMap, false, 0},
	{"{1: 2, 3: 4}", "a201020304", majorMap, false, 2},
	{"{\"a\": 1, \"b\": [2, 3]}", "a26161016162820203", majorMap, false, 2},
	{"[\"a\", {\"b\": \"c\"}]", "826161a161626163", majorArray, false, 0},
	{"{\"a\": \"A\", \"b\": \"B\", \"c\": \"C\", \"d\": \"D\", \"e\": \"E\"}", "a56161614161626142616361436164614461656145", majorMap, false, 5},
	{"(_ h'0102', h'030405')", "5f42010243030405ff", majorBytes, true, 0},
	{"(_ \"strea\", \"ming\")", "7f657374726561646d696e67ff", majorText, true, 0},
	{"[_ ]", "9fff", majorArray, true, 0},
	{"[_ 1, [2, 3], [_ 4, 5]]", "9f018202039f0405ffff", majorArray, true, 0},
	{"[_ 1, [2, 3], [4, 5]]", "9f01820203820405ff", majorArray, true, 0},
	{"[1, [2, 3], [_ 4, 5]]", "83018202039f0405ff", majorArray, false, 0},
	{"[1, [_ 2, 3], [4, 5]]", "83019f0203ff820405", majorArray, false, 0},
	{"[_ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]", "9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff", majorArray, true, 0},
	{"{_ \"a\": 1, \"b\": [_ 2, 3]}", "bf61610161629f0203ffff", majorMap, true, 0},
	{"[\"a\", {_ \"b\": \"c\"}]", "826161bf61626163ff", majorArray, false, 0},
	{"{_ \"Fun\": true, \"Amt\": -2}", "bf6346756ef563416d7421ff", majorMap, true, 0},
}
