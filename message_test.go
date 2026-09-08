package llmnr_test

import (
	"encoding/hex"
	"strings"
	"testing"

	llmnr "github.com/dmgedgoods/llmnr-parser"
)

func payloadHex(t *testing.T, s string) []byte {
	t.Helper()
	data, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDecodeMessageCapture(t *testing.T) {
	for _, tc := range []struct {
		name, wire, address string
		id, recordType      uint16
	}{
		{"A query frames429and430", "e221000000010000000000000267310000010001", "", 0xe221, 1},
		{"AAAA query frames431and432", "dd840000000100000000000002673100001c0001", "", 0xdd84, 28},
		{"A response frames435and437", "e22180000001000100000000026731000001000102673100000100010000001e0004c0a801b1", "192.168.1.177", 0xe221, 1},
		{"AAAA response frames436and438", "dd848000000100010000000002673100001c000102673100001c00010000001e0010fe80000000000000b871eca9c39b9fed", "fe80::b871:eca9:c39b:9fed", 0xdd84, 28},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := llmnr.DecodeMessage(payloadHex(t, tc.wire))
			if err != nil {
				t.Fatal(err)
			}
			if m.Header.ID != tc.id || m.Header.QR != (tc.address != "") || len(m.Questions) != 1 {
				t.Fatalf("unexpected message: %+v", m)
			}
			if m.Questions[0] != (llmnr.Question{Name: "g1", Type: tc.recordType, Class: 1}) {
				t.Fatalf("unexpected question: %+v", m.Questions[0])
			}
			if tc.address == "" {
				if len(m.Answers) != 0 {
					t.Fatal("query has answers")
				}
			} else {
				if len(m.Answers) != 1 {
					t.Fatalf("answer count = %d", len(m.Answers))
				}
				a := m.Answers[0]
				if a.Name != "g1" || a.Type != tc.recordType || a.Class != 1 || a.TTL != 30 || a.Address.String() != tc.address {
					t.Fatalf("unexpected answer: %+v", a)
				}
			}
		})
	}
}

func TestDecodeMessageSyntheticMultipleAnswers(t *testing.T) {
	// Hand-authored wire data: ID 0x1234, response, one A question, two A
	// answers with distinct addresses and TTLs. No production encoder is used.
	data := payloadHex(t, `
		1234 8000 0001 0002 0000 0000
		02673100 0001 0001
		02673100 0001 0001 0000001e 0004 c0000201
		02673100 0001 0001 0000003c 0004 c0000202`)
	m, err := llmnr.DecodeMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Answers) != 2 {
		t.Fatalf("answer count = %d", len(m.Answers))
	}
	for i, want := range []struct {
		address string
		ttl     uint32
	}{{"192.0.2.1", 30}, {"192.0.2.2", 60}} {
		a := m.Answers[i]
		if a.Name != "g1" || a.Type != 1 || a.Class != 1 || a.Address.String() != want.address || a.TTL != want.ttl {
			t.Errorf("answer %d: %+v", i+1, a)
		}
	}
	// Capture readers may reuse their buffers; decoded records must survive.
	clear(data)
	if hex.EncodeToString(m.Answers[0].RData) != "c0000201" || m.Answers[0].Address.String() != "192.0.2.1" {
		t.Fatal("decoded record changed with input buffer")
	}
}

func TestDecodeMessageSyntheticOpaqueRecord(t *testing.T) {
	data := payloadHex(t, `1234 8000 0001 0001 0000 0000
		02673100 ff00 0001
		02673100 ff00 0001 0000001e 0003 aabbcc`)
	m, err := llmnr.DecodeMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	a := m.Answers[0]
	if a.Type != 0xff00 || a.Address.IsValid() || hex.EncodeToString(a.RData) != "aabbcc" {
		t.Fatalf("opaque record not preserved: %+v", a)
	}
}

func TestDecodeMessageSyntheticFailures(t *testing.T) {
	const header = "1234 8000 0001 0001 0000 0000 "
	const question = "02673100 0001 0001 "
	for _, tc := range []struct{ name, wire, want string }{
		{"missing question", "1234 0000 0001 0000 0000 0000", "question 1"},
		{"missing second question", "1234 0000 0002 0000 0000 0000 " + question, "question 2"},
		{"missing answer", header + question, "answer 1"},
		{"missing second answer", "1234 8000 0001 0002 0000 0000 " + question + "02673100 0001 0001 0000001e 0004 c0000201", "answer 2"},
		{"short fields", header + question + "02673100 0001", "short resource record fields"},
		{"short data", header + question + "02673100 0001 0001 0000001e 0004 c00002", "short record data"},
		{"wrong A length", header + question + "02673100 0001 0001 0000001e 0003 c00002", "A record data length"},
		{"wrong AAAA length", header + question + "02673100 001c 0001 0000001e 0004 c0000201", "AAAA record data length"},
		{"trailing bytes", "1234 0000 0001 0000 0000 0000 " + question + "ff", "trailing bytes"},
		{"missing authority", "1234 8000 0000 0000 0001 0000", "authority 1"},
		{"missing additional", "1234 8000 0000 0000 0000 0001", "additional 1"},
		{"compression deferred", header + question + "c00c 0001 0001 0000001e 0004 c0000201", "compression not supported yet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := llmnr.DecodeMessage(payloadHex(t, tc.wire))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if m != nil {
				t.Fatal("returned partial message on error")
			}
		})
	}
}

func TestDecodeMessageEveryTruncatedPrefix(t *testing.T) {
	data := payloadHex(t, "e22180000001000100000000026731000001000102673100000100010000001e0004c0a801b1")
	for n := 0; n < len(data); n++ {
		if m, err := llmnr.DecodeMessage(data[:n]); err == nil || m != nil {
			t.Errorf("length %d: got %+v, %v", n, m, err)
		}
	}
}
