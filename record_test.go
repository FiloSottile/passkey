package passkey

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"filippo.io/mldsa"
)

var updateFlag = flag.Bool("update", false, "regenerate testdata files")

// recordVector is a passkey record parsing test vector, in the format
// of testdata/records.json, meant to be shareable with other
// implementations of c2sp.org/passkey-record.
//
// A vector with an error reason must fail to parse. A vector without
// one must parse to the given fields and must re-encode to canonical,
// or to record itself if canonical is empty.
//
// Algorithm is the COSE algorithm of the credential public key embedded
// in the record, when one is identifiable. An implementation that does
// not support that algorithm can skip the vector, or check that it
// rejects the record as unsupported.
type recordVector struct {
	Name         string       `json:"name"`
	Record       string       `json:"record"`
	Algorithm    int32        `json:"algorithm,omitzero"`
	Error        string       `json:"error,omitempty"`
	Canonical    string       `json:"canonical,omitempty"`
	AAGUID       string       `json:"aaguid,omitempty"`
	CredentialID string       `json:"credentialId,omitempty"`
	Transports   *[]string    `json:"transports,omitempty"`
	Flags        *recordFlags `json:"flags,omitempty"`
}

type recordFlags struct {
	UP bool `json:"UP"` // user present
	UV bool `json:"UV"` // user verified
	BE bool `json:"BE"` // backup eligible
	BS bool `json:"BS"` // backup state
	AT bool `json:"AT"` // attested credential data included
	ED bool `json:"ED"` // extension data included
}

// recordVectorErrors maps the machine-readable error reasons of
// testdata/records.json to this package's error messages.
var recordVectorErrors = map[string]string{
	"bad-prefix":                       "invalid record",
	"bad-version":                      "invalid record",
	"bad-base64":                       "invalid record",
	"bad-parameter":                    "invalid parameters",
	"duplicate-transports-parameter":   "duplicate transports parameter",
	"invalid-transport":                "invalid transport",
	"transports-not-sorted":            "not sorted and deduplicated",
	"too-many-transports":              "too many transports",
	"authenticator-data-too-short":     "expected at least 55",
	"authenticator-data-too-long":      "expected at most 8192",
	"no-attested-credential-data":      "no attested credential data",
	"backup-state-without-eligibility": "backed up but not backup eligible",
	"bad-credential-id-length":         "credential ID is",
	"credential-id-truncated":          "too short for the credential ID",
	"extension-data-missing":           "claims extension data but has none",
	"unexpected-trailing-data":         "unexpected trailing bytes",
	"bad-cose-key":                     "malformed COSE key",
	"unsupported-algorithm":            "unsupported credential public key algorithm",
	"unsupported-rsa-modulus-size":     "unsupported RSA modulus size",
}

// TestRecordVectors runs the testdata/records.json vectors: the record
// grammar (prefix, version, parameters, transports, base64 field), the
// authenticator data constraints, and the COSE key grammar, all through
// full records and the exported accessors. Valid vectors double as
// round-trip tests, and vectors for algorithms this package does not
// support must fail with ErrUnsupportedAlgorithm.
//
// Regenerate the file with go test -run TestRecordVectors -update.
func TestRecordVectors(t *testing.T) {
	if *updateFlag {
		writeRecordVectors(t)
	}
	data, err := os.ReadFile("testdata/records.json")
	if err != nil {
		t.Fatalf("%v (regenerate with -update)", err)
	}
	var vectors []recordVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			aaguid, err := AAGUID(v.Record)
			if v.Error != "" {
				errHas, ok := recordVectorErrors[v.Error]
				if !ok {
					t.Fatalf("unknown error reason %q", v.Error)
				}
				if err == nil {
					t.Fatalf("AAGUID() succeeded, want %s error", v.Error)
				}
				if !strings.Contains(err.Error(), errHas) {
					t.Errorf("AAGUID() = %v, want it to contain %q", err, errHas)
				}
				if v.Error == "unsupported-algorithm" && !errors.Is(err, ErrUnsupportedAlgorithm) {
					t.Errorf("AAGUID() = %v, want errors.Is(err, ErrUnsupportedAlgorithm)", err)
				}
				return
			}

			// Valid records with an algorithm this package does not
			// support are rejected with ErrUnsupportedAlgorithm.
			switch v.Algorithm {
			case algES256, algRS256, algMLDSA44:
			default:
				if !errors.Is(err, ErrUnsupportedAlgorithm) {
					t.Errorf("AAGUID() = %v, want errors.Is(err, ErrUnsupportedAlgorithm)", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("AAGUID() = %v, want success", err)
			}
			if v.Transports == nil || v.Flags == nil {
				t.Fatal("vector is missing expected fields")
			}
			if got := hex.EncodeToString(aaguid[:]); got != v.AAGUID {
				t.Errorf("AAGUID() = %s, want %s", got, v.AAGUID)
			}
			transports, err := Transports(v.Record)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(transports, *v.Transports) {
				t.Errorf("Transports() = %q, want %q", transports, *v.Transports)
			}
			backedUp, err := BackedUp(v.Record)
			if err != nil {
				t.Fatal(err)
			}
			if backedUp != v.Flags.BS {
				t.Errorf("BackedUp() = %v, want %v", backedUp, v.Flags.BS)
			}
			// The credential ID and the flags other than BS have no
			// exported accessor.
			r, err := parseRecord(v.Record)
			if err != nil {
				t.Fatal(err)
			}
			decoded := recordFlags{
				UP: r.flags.userPresent(),
				UV: r.flags.userVerified(),
				BE: r.flags.backupEligible(),
				BS: r.flags.backupState(),
				AT: r.flags.attestedData(),
				ED: r.flags.extensionData(),
			}
			if decoded != *v.Flags {
				t.Errorf("flags = %+v, want %+v", decoded, *v.Flags)
			}
			if got := hex.EncodeToString(r.credentialID); got != v.CredentialID {
				t.Errorf("credentialID = %s, want %s", got, v.CredentialID)
			}

			ad, err := base64.RawStdEncoding.Strict().DecodeString(v.Record[strings.LastIndex(v.Record, "$")+1:])
			if err != nil {
				t.Fatal(err)
			}
			want := v.Record
			if v.Canonical != "" {
				want = v.Canonical
			}
			if got := encodeRecord(ad, transports); got != want {
				t.Errorf("re-encoded record = %q, want %q", got, want)
			}
		})
	}
}

func writeRecordVectors(t *testing.T) {
	t.Helper()
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	aaguid := make([]byte, 16)
	for i := range aaguid {
		aaguid[i] = byte(i)
	}
	credentialID := make([]byte, 32)
	for i := range credentialID {
		credentialID[i] = byte(0x10 + i)
	}

	// authData assembles registration authenticator data for the vector
	// RP ID. The attested credential data is included iff the AT flag is
	// set, and extensions are appended regardless of the ED flag, so that
	// inconsistent combinations can be produced.
	authData := func(flags byte, credentialID, coseKey, extensions []byte) []byte {
		rpIDHash := sha256.Sum256([]byte(testRPID))
		b := append([]byte{}, rpIDHash[:]...)
		b = append(b, flags)
		b = binary.BigEndian.AppendUint32(b, 0) // signature counter
		if flags&flagAT != 0 {
			b = append(b, aaguid...)
			b = binary.BigEndian.AppendUint16(b, uint16(len(credentialID)))
			b = append(b, credentialID...)
			b = append(b, coseKey...)
		}
		return append(b, extensions...)
	}

	ec2Key := func(alg, crv int32, x, y []byte, yLabel int32) []byte {
		k := cborAppendMapHeader(nil, 5)
		k = cborAppendInt(k, 1)
		k = cborAppendInt(k, coseKeyTypeEC2)
		k = cborAppendInt(k, 3)
		k = cborAppendInt(k, alg)
		k = cborAppendInt(k, -1)
		k = cborAppendInt(k, crv)
		k = cborAppendInt(k, -2)
		k = cborAppendBytes(k, x)
		k = cborAppendInt(k, yLabel)
		k = cborAppendBytes(k, y)
		return k
	}
	rsaKey := func(n, e []byte) []byte {
		k := cborAppendMapHeader(nil, 4)
		k = cborAppendInt(k, 1)
		k = cborAppendInt(k, coseKeyTypeRSA)
		k = cborAppendInt(k, 3)
		k = cborAppendInt(k, algRS256)
		k = cborAppendInt(k, -1)
		k = cborAppendBytes(k, n)
		k = cborAppendInt(k, -2)
		k = cborAppendBytes(k, e)
		return k
	}
	akpKey := func(alg int32, pub []byte) []byte {
		k := cborAppendMapHeader(nil, 3)
		k = cborAppendInt(k, 1)
		k = cborAppendInt(k, coseKeyTypeAKP)
		k = cborAppendInt(k, 3)
		k = cborAppendInt(k, alg)
		k = cborAppendInt(k, -1)
		k = cborAppendBytes(k, pub)
		return k
	}
	withMapHeader := func(key []byte, header byte) []byte {
		key = slices.Clone(key)
		key[0] = header
		return key
	}

	// The P-256 generator point, as deterministic valid key material.
	gx := mustHex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
	gy := mustHex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	es256 := ec2Key(algES256, coseCurveP256, gx, gy, -3)

	// A fabricated RSA modulus: record parsing checks the size of the
	// key material, not its validity.
	rsaN := make([]byte, 256)
	rsaN[0], rsaN[255] = 0x80, 0x01
	rs256 := rsaKey(rsaN, []byte{0x01, 0x00, 0x01})

	mldsaSeed := bytes.Repeat([]byte{0x42}, 32)
	akpPub := func(params *mldsa.Parameters) []byte {
		key, err := mldsa.NewPrivateKey(params, mldsaSeed)
		if err != nil {
			t.Fatal(err)
		}
		return key.PublicKey().Bytes()
	}
	mldsa44Pub := akpPub(mldsa.MLDSA44())
	mldsa44 := akpKey(algMLDSA44, mldsa44Pub)
	mldsa65 := akpKey(algMLDSA65, akpPub(mldsa.MLDSA65()))
	mldsa87 := akpKey(algMLDSA87, akpPub(mldsa.MLDSA87()))

	okp := cborAppendMapHeader(nil, 3)
	okp = cborAppendInt(okp, 1)
	okp = cborAppendInt(okp, 1) // kty OKP
	okp = cborAppendInt(okp, 3)
	okp = cborAppendInt(okp, -8)
	okp = cborAppendInt(okp, -1)
	okp = cborAppendBytes(okp, make([]byte, 32))

	nonMinimalAlg := cborAppendMapHeader(nil, 5)
	nonMinimalAlg = cborAppendInt(nonMinimalAlg, 1)
	nonMinimalAlg = cborAppendInt(nonMinimalAlg, coseKeyTypeEC2)
	nonMinimalAlg = cborAppendInt(nonMinimalAlg, 3)
	nonMinimalAlg = append(nonMinimalAlg, 0x38, 0x06) // -7 with a redundant argument byte
	nonMinimalAlg = cborAppendInt(nonMinimalAlg, -1)
	nonMinimalAlg = cborAppendInt(nonMinimalAlg, coseCurveP256)
	nonMinimalAlg = cborAppendInt(nonMinimalAlg, -2)
	nonMinimalAlg = cborAppendBytes(nonMinimalAlg, gx)
	nonMinimalAlg = cborAppendInt(nonMinimalAlg, -3)
	nonMinimalAlg = cborAppendBytes(nonMinimalAlg, gy)

	nonMinimalLen := cborAppendMapHeader(nil, 5)
	nonMinimalLen = cborAppendInt(nonMinimalLen, 1)
	nonMinimalLen = cborAppendInt(nonMinimalLen, coseKeyTypeEC2)
	nonMinimalLen = cborAppendInt(nonMinimalLen, 3)
	nonMinimalLen = cborAppendInt(nonMinimalLen, algES256)
	nonMinimalLen = cborAppendInt(nonMinimalLen, -1)
	nonMinimalLen = cborAppendInt(nonMinimalLen, coseCurveP256)
	nonMinimalLen = cborAppendInt(nonMinimalLen, -2)
	nonMinimalLen = append(nonMinimalLen, 0x59, 0x00, 0x20) // 32-byte length with a two-byte argument
	nonMinimalLen = append(nonMinimalLen, gx...)
	nonMinimalLen = cborAppendInt(nonMinimalLen, -3)
	nonMinimalLen = cborAppendBytes(nonMinimalLen, gy)

	// flagsOf describes a flags byte in terms of the test's own bit
	// constants, independently of the accessors under test.
	flagsOf := func(f byte) *recordFlags {
		return &recordFlags{
			UP: f&flagUP != 0,
			UV: f&flagUV != 0,
			BE: f&flagBE != 0,
			BS: f&flagBS != 0,
			AT: f&flagAT != 0,
			ED: f&flagED != 0,
		}
	}

	baseFlags := flagUP | flagAT
	base := authData(baseFlags, credentialID, es256, nil)
	baseB64 := base64.RawStdEncoding.EncodeToString(base)
	aaguidHex := hex.EncodeToString(aaguid)
	credentialIDHex := hex.EncodeToString(credentialID)

	// withKey embeds a COSE key in otherwise valid authenticator data.
	withKey := func(coseKey []byte) string {
		return encodeRecord(authData(flagUP|flagAT, credentialID, coseKey, nil), nil)
	}
	// A record with no transports lists them as an empty array, not
	// null, which JSON round-trips indistinguishably from an absent field.
	transportsPtr := func(transports ...string) *[]string {
		if transports == nil {
			transports = []string{}
		}
		return &transports
	}
	valid := func(name string, alg int32, flags byte, coseKey []byte, transports []string) recordVector {
		return recordVector{
			Name:         name,
			Record:       encodeRecord(authData(flags, credentialID, coseKey, nil), transports),
			Algorithm:    alg,
			AAGUID:       aaguidHex,
			CredentialID: credentialIDHex,
			Transports:   transportsPtr(transports...),
			Flags:        flagsOf(flags),
		}
	}
	invalid := func(name, record, reason string, alg int32) recordVector {
		if _, ok := recordVectorErrors[reason]; !ok {
			t.Fatalf("unknown error reason %q", reason)
		}
		return recordVector{Name: name, Record: record, Error: reason, Algorithm: alg}
	}

	minID := credentialID[:16]
	maxID := make([]byte, 1023)
	for i := range maxID {
		maxID[i] = byte(i)
	}

	// nonCanonicalBase64 sets the unused trailing bits of the last
	// character, which decode to the same bytes but are rejected by a
	// strict decoder.
	nonCanonicalBase64 := func(b64 string) string {
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		v := strings.IndexByte(alphabet, b64[len(b64)-1])
		switch len(b64) % 4 {
		case 2: // the last character carries four unused bits
			v |= 0b1111
		case 3: // the last character carries two unused bits
			v |= 0b11
		default:
			t.Fatal("base64 length leaves no trailing bits to set")
		}
		out := b64[:len(b64)-1] + string(alphabet[v])
		if _, err := base64.RawStdEncoding.Strict().DecodeString(out); err == nil {
			t.Fatal("strict decoder accepted non-canonical base64")
		}
		if _, err := base64.RawStdEncoding.DecodeString(out); err != nil {
			t.Fatal("lenient decoder rejected non-canonical base64")
		}
		return out
	}

	// A record whose base64 is guaranteed to contain the '/' character,
	// to derive the URL-alphabet vector from.
	slashes := encodeRecord(authData(flagUP|flagAT|flagED, credentialID, es256, []byte{0xff, 0xff, 0xff}), nil)
	if !strings.Contains(slashes, "/") {
		t.Fatal("no '/' in the base64 field to substitute")
	}

	var manyTransports []string
	for i := range 33 {
		manyTransports = append(manyTransports, fmt.Sprintf("t%02d", i))
	}

	vectors := []recordVector{
		valid("es256", algES256, flagUP|flagAT, es256, nil),
		valid("es256-with-transports", algES256, flagUP|flagAT, es256, []string{"hybrid", "internal"}),
		valid("rs256", algRS256, flagUP|flagAT, rs256, nil),
		valid("ml-dsa-44", algMLDSA44, flagUP|flagAT, mldsa44, nil),
		valid("ml-dsa-65", algMLDSA65, flagUP|flagAT, mldsa65, nil),
		valid("ml-dsa-87", algMLDSA87, flagUP|flagAT, mldsa87, nil),
		valid("no-user-presence", algES256, flagAT, es256, nil),
		valid("user-verified", algES256, flagUP|flagUV|flagAT, es256, nil),
		valid("backup-eligible", algES256, flagUP|flagAT|flagBE, es256, nil),
		valid("backed-up", algES256, flagUP|flagAT|flagBE|flagBS, es256, nil),
		valid("transport-alphabet", algES256, flagUP|flagAT, es256, []string{"A-B", "a.b", "a/b", "z0-9"}),
		{
			Name:         "extension-data",
			Record:       encodeRecord(authData(flagUP|flagAT|flagED, credentialID, es256, []byte{0xa0}), nil),
			Algorithm:    algES256,
			AAGUID:       aaguidHex,
			CredentialID: credentialIDHex,
			Transports:   transportsPtr(),
			Flags:        flagsOf(flagUP | flagAT | flagED),
		},
		{
			Name:         "unknown-parameter",
			Record:       "$webauthn$v=1$foo=bar$" + baseB64,
			Algorithm:    algES256,
			Canonical:    "$webauthn$v=1$" + baseB64,
			AAGUID:       aaguidHex,
			CredentialID: credentialIDHex,
			Transports:   transportsPtr(),
			Flags:        flagsOf(baseFlags),
		},
		{
			Name:         "unknown-parameter-before-transports",
			Record:       "$webauthn$v=1$foo=bar,transports=usb$" + baseB64,
			Algorithm:    algES256,
			Canonical:    "$webauthn$v=1$transports=usb$" + baseB64,
			AAGUID:       aaguidHex,
			CredentialID: credentialIDHex,
			Transports:   transportsPtr("usb"),
			Flags:        flagsOf(baseFlags),
		},
		{
			Name:         "unknown-parameter-after-transports",
			Record:       "$webauthn$v=1$transports=usb,foo=bar$" + baseB64,
			Algorithm:    algES256,
			Canonical:    "$webauthn$v=1$transports=usb$" + baseB64,
			AAGUID:       aaguidHex,
			CredentialID: credentialIDHex,
			Transports:   transportsPtr("usb"),
			Flags:        flagsOf(baseFlags),
		},
		{
			Name:         "minimum-credential-id",
			Record:       encodeRecord(authData(baseFlags, minID, es256, nil), nil),
			Algorithm:    algES256,
			AAGUID:       aaguidHex,
			CredentialID: hex.EncodeToString(minID),
			Transports:   transportsPtr(),
			Flags:        flagsOf(baseFlags),
		},
		{
			Name:         "maximum-credential-id",
			Record:       encodeRecord(authData(baseFlags, maxID, es256, nil), nil),
			Algorithm:    algES256,
			AAGUID:       aaguidHex,
			CredentialID: hex.EncodeToString(maxID),
			Transports:   transportsPtr(),
			Flags:        flagsOf(baseFlags),
		},

		invalid("missing-prefix", "webauthn$v=1$"+baseB64, "bad-prefix", algES256),
		invalid("unknown-version", "$webauthn$v=2$"+baseB64, "bad-version", algES256),
		invalid("empty-authenticator-data", "$webauthn$v=1$", "authenticator-data-too-short", 0),
		invalid("base64-padding", "$webauthn$v=1$"+baseB64+"=", "bad-base64", algES256),
		invalid("base64-newline", "$webauthn$v=1$"+baseB64[:10]+"\n"+baseB64[10:], "bad-base64", algES256),
		invalid("base64-carriage-return", "$webauthn$v=1$"+baseB64[:10]+"\r"+baseB64[10:], "bad-base64", algES256),
		invalid("base64-url-alphabet", strings.Replace(slashes, "/", "_", 1), "bad-base64", algES256),
		invalid("base64-non-canonical-bits", "$webauthn$v=1$"+nonCanonicalBase64(baseB64), "bad-base64", algES256),
		invalid("empty-parameter-value", "$webauthn$v=1$transports=$"+baseB64, "bad-parameter", algES256),
		invalid("parameter-without-value", "$webauthn$v=1$transports$"+baseB64, "bad-parameter", algES256),
		invalid("trailing-parameter-comma", "$webauthn$v=1$transports=usb,$"+baseB64, "bad-parameter", algES256),
		invalid("leading-parameter-comma", "$webauthn$v=1$,transports=usb$"+baseB64, "bad-parameter", algES256),
		invalid("duplicate-transports-parameter", "$webauthn$v=1$transports=a,transports=b$"+baseB64, "duplicate-transports-parameter", algES256),
		invalid("transport-invalid-character", "$webauthn$v=1$transports=a b$"+baseB64, "invalid-transport", algES256),
		invalid("transport-empty", "$webauthn$v=1$transports=a+$"+baseB64, "invalid-transport", algES256),
		invalid("transports-unsorted", "$webauthn$v=1$transports=usb+internal$"+baseB64, "transports-not-sorted", algES256),
		invalid("transports-duplicated", "$webauthn$v=1$transports=usb+usb$"+baseB64, "transports-not-sorted", algES256),
		invalid("too-many-transports", "$webauthn$v=1$transports="+strings.Join(manyTransports, "+")+"$"+baseB64, "too-many-transports", algES256),
		invalid("authenticator-data-too-short", encodeRecord(make([]byte, 54), nil), "authenticator-data-too-short", 0),
		invalid("authenticator-data-too-long", encodeRecord(authData(flagUP|flagAT|flagED, credentialID, es256, make([]byte, 8200)), nil), "authenticator-data-too-long", algES256),
		invalid("no-attested-credential-data", encodeRecord(authData(flagUP|flagED, nil, nil, make([]byte, 18)), nil), "no-attested-credential-data", 0),
		invalid("backup-state-without-eligibility", encodeRecord(authData(flagUP|flagAT|flagBS, credentialID, es256, nil), nil), "backup-state-without-eligibility", algES256),
		invalid("credential-id-too-short", encodeRecord(authData(flagUP|flagAT, credentialID[:15], es256, nil), nil), "bad-credential-id-length", algES256),
		invalid("credential-id-too-long", encodeRecord(authData(flagUP|flagAT, make([]byte, 1024), es256, nil), nil), "bad-credential-id-length", algES256),
		invalid("credential-id-truncated", encodeRecord(base[:32+1+4+16+2+8], nil), "credential-id-truncated", 0),
		invalid("extension-data-claimed-but-absent", encodeRecord(authData(flagUP|flagAT|flagED, credentialID, es256, nil), nil), "extension-data-missing", algES256),
		invalid("trailing-data-without-extension-flag", encodeRecord(authData(flagUP|flagAT, credentialID, es256, []byte{0x01, 0x02, 0x03}), nil), "unexpected-trailing-data", algES256),

		invalid("cose-truncated", withKey([]byte{0xff}), "bad-cose-key", 0),
		invalid("cose-ec2-map-length", withKey(withMapHeader(es256, 0xa4)), "bad-cose-key", algES256),
		invalid("cose-rsa-map-length", withKey(withMapHeader(rs256, 0xa5)), "bad-cose-key", algRS256),
		invalid("cose-akp-map-length", withKey(withMapHeader(mldsa44, 0xa4)), "bad-cose-key", algMLDSA44),
		invalid("cose-non-minimal-integer", withKey(nonMinimalAlg), "bad-cose-key", algES256),
		invalid("cose-non-minimal-length", withKey(nonMinimalLen), "bad-cose-key", algES256),
		invalid("cose-unknown-label", withKey(ec2Key(algES256, coseCurveP256, gx, gy, -4)), "bad-cose-key", algES256),
		invalid("cose-ec2-wrong-curve", withKey(ec2Key(algES256, 2, gx, gy, -3)), "bad-cose-key", algES256),
		invalid("cose-ec2-short-coordinate", withKey(ec2Key(algES256, coseCurveP256, gx[:31], gy, -3)), "bad-cose-key", algES256),
		// x and y are 33 and 31 bytes, but their concatenation is the
		// same valid point: only the coordinate length checks reject it.
		invalid("cose-ec2-coordinate-length-confusion",
			withKey(ec2Key(algES256, coseCurveP256, append(slices.Clone(gx), gy[0]), gy[1:], -3)),
			"bad-cose-key", algES256),
		invalid("cose-ec2-invalid-point", withKey(ec2Key(algES256, coseCurveP256, make([]byte, 32), make([]byte, 32), -3)), "bad-cose-key", algES256),
		invalid("cose-ec2-es384", withKey(ec2Key(-35, coseCurveP256, gx, gy, -3)), "unsupported-algorithm", -35),
		invalid("cose-okp-key-type", withKey(okp), "unsupported-algorithm", -8),
		invalid("cose-rsa-modulus-leading-zero", withKey(rsaKey(append([]byte{0x00}, rsaN...), []byte{0x03})), "bad-cose-key", algRS256),
		invalid("cose-rsa-modulus-too-small", withKey(rsaKey(rsaN[:128], []byte{0x03})), "unsupported-rsa-modulus-size", algRS256),
		invalid("cose-rsa-modulus-too-large", withKey(rsaKey(append([]byte{0x80}, make([]byte, 512)...), []byte{0x03})), "unsupported-rsa-modulus-size", algRS256),
		invalid("cose-rsa-exponent-even", withKey(rsaKey(rsaN, []byte{0x01, 0x00, 0x02})), "bad-cose-key", algRS256),
		invalid("cose-rsa-exponent-one", withKey(rsaKey(rsaN, []byte{0x01})), "bad-cose-key", algRS256),
		invalid("cose-rsa-exponent-leading-zero", withKey(rsaKey(rsaN, []byte{0x00, 0x03})), "bad-cose-key", algRS256),
		invalid("cose-rsa-exponent-too-long", withKey(rsaKey(rsaN, []byte{0x01, 0x00, 0x00, 0x00, 0x01})), "bad-cose-key", algRS256),
		invalid("cose-akp-wrong-key-size", withKey(akpKey(algMLDSA44, mldsa44Pub[:1311])), "bad-cose-key", algMLDSA44),
	}

	data, err := json.MarshalIndent(vectors, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll("testdata", 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("testdata/records.json", data, 0o666); err != nil {
		t.Fatal(err)
	}
}
