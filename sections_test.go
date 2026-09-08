package llmnr_test

import (
	"encoding/hex"
	"strings"
	"testing"

	llmnr "github.com/dmgedgoods/llmnr-parser"
)

// An uncompressed SOA: MNAME g1, RNAME root, followed by SERIAL, REFRESH,
// RETRY, EXPIRE and MINIMUM. Its 25-byte RDATA remains opaque in this chunk.
const syntheticSOAData = "02673100 00 00000001 0000003c 0000001e 00000078 0000000f"
const syntheticSOA = "02673100 0006 0001 0000000f 0019 " + syntheticSOAData
const syntheticOPT = "00 0029 04d0 00000000 0000" // root, OPT, UDP size 1232, no options

func TestDecodeMessageSyntheticNegativeResponses(t *testing.T) {
	for _, withSOA := range []bool{false, true} {
		name, wire := "without SOA", "1234 8000 0001 0000 0000 0000 02673100 001c 0001"
		if withSOA {
			name, wire = "with SOA", "1234 8000 0001 0000 0001 0000 02673100 001c 0001 "+syntheticSOA
		}
		t.Run(name, func(t *testing.T) {
			m, err := llmnr.DecodeMessage(payloadHex(t, wire))
			if err != nil {
				t.Fatal(err)
			}
			if !m.Header.QR || m.Header.RCode != 0 || len(m.Answers) != 0 || len(m.Additionals) != 0 {
				t.Fatalf("unexpected negative response: %+v", m)
			}
			if !withSOA {
				if len(m.Authorities) != 0 {
					t.Fatal("invented authority record")
				}
				return
			}
			if len(m.Authorities) != 1 {
				t.Fatalf("authority count: %d", len(m.Authorities))
			}
			a := m.Authorities[0]
			if a.Name != "g1" || a.Type != 6 || a.Class != 1 || a.TTL != 15 || a.RDLength != 25 || a.Address.IsValid() {
				t.Fatalf("unexpected SOA: %+v", a)
			}
			if hex.EncodeToString(a.RData) != strings.ReplaceAll(syntheticSOAData, " ", "") {
				t.Fatalf("SOA bytes: %x", a.RData)
			}
		})
	}
}

func TestDecodeMessageSyntheticAdditionalQueryRecords(t *testing.T) {
	for _, tc := range []struct {
		name, flags, record string
		recordType          uint16
	}{
		{"EDNS0 query", "0000", syntheticOPT, 41},
		{"conflict notification", "0400", "02673100 0001 0001 0000001e 0004 c0000201", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := llmnr.DecodeMessage(payloadHex(t, "1234 "+tc.flags+" 0001 0000 0000 0001 02673100 0001 0001 "+tc.record))
			if err != nil {
				t.Fatal(err)
			}
			if m.Header.QR || m.Header.Conflict != (tc.flags == "0400") || len(m.Answers) != 0 || len(m.Authorities) != 0 || len(m.Additionals) != 1 {
				t.Fatalf("wrong section placement: %+v", m)
			}
			a := m.Additionals[0]
			if a.Type != tc.recordType {
				t.Fatalf("type = %d", a.Type)
			}
			if tc.recordType == 41 {
				if a.Name != "." || a.Class != 1232 || a.TTL != 0 || len(a.RData) != 0 || a.Address.IsValid() {
					t.Fatalf("OPT fields changed: %+v", a)
				}
			} else if a.Address.String() != "192.0.2.1" {
				t.Fatalf("conflicting address = %v", a.Address)
			}
		})
	}
}

func TestDecodeMessageSyntheticSectionBoundaries(t *testing.T) {
	// Structural fixture exercises all three RR sections, with two additional
	// records. It is not a claim that a responder should emit this combination.
	data := payloadHex(t, "1234 8000 0001 0001 0001 0002 02673100 0001 0001 "+
		"02673100 0001 0001 0000001e 0004 c0000201 "+syntheticSOA+" "+syntheticOPT+
		" 02673100 ff00 0001 00000000 0002 aabb")
	m, err := llmnr.DecodeMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Answers) != 1 || len(m.Authorities) != 1 || len(m.Additionals) != 2 {
		t.Fatalf("wrong section counts: %+v", m)
	}
	if m.Answers[0].Type != 1 || m.Authorities[0].Type != 6 || m.Additionals[0].Type != 41 || m.Additionals[1].Type != 0xff00 {
		t.Fatal("records crossed section boundaries or reordered")
	}
	clear(data)
	if hex.EncodeToString(m.Additionals[1].RData) != "aabb" || hex.EncodeToString(m.Authorities[0].RData) != strings.ReplaceAll(syntheticSOAData, " ", "") {
		t.Fatal("records changed after buffer reuse")
	}
}

func TestDecodeMessageSyntheticSectionTruncation(t *testing.T) {
	for _, section := range []string{"authority", "additional"} {
		t.Run(section, func(t *testing.T) {
			counts := "0001 0000"
			if section == "additional" {
				counts = "0000 0001"
			}
			data := payloadHex(t, "1234 8000 0001 0000 "+counts+" 02673100 001c 0001 "+syntheticSOA)
			// Every truncation inside this section must identify it and return no
			// partial message, even when the header and question decoded correctly.
			for n := 20; n < len(data); n++ {
				m, err := llmnr.DecodeMessage(data[:n])
				if err == nil || !strings.Contains(err.Error(), section+" 1") || m != nil {
					t.Fatalf("prefix %d: message=%+v, error=%v", n, m, err)
				}
			}
			// Two declared records but only one encoded.
			if section == "authority" {
				data[9] = 2
			} else {
				data[11] = 2
			}
			if m, err := llmnr.DecodeMessage(data); err == nil || !strings.Contains(err.Error(), section+" 2") || m != nil {
				t.Fatalf("count mismatch: message=%+v, error=%v", m, err)
			}
		})
	}
}
