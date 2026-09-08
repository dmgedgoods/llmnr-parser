package llmnr_test

import (
	"encoding/hex"
	"testing"

	llmnr "github.com/dmgedgoods/llmnr-parser"
)

func TestDecodeResourceRecordCapture(t *testing.T) {
	// Each pair has identical LLMNR payloads over IPv6 and IPv4 respectively.
	// Expected fields and literal bytes come from the saved TShark baseline.
	for _, tc := range []struct {
		name, payload, address, rdata string
		wantType, length              uint16
		end                           int
	}{
		{
			"frames435and437",
			"e22180000001000100000000026731000001000102673100000100010000001e0004c0a801b1",
			"192.168.1.177", "c0a801b1", 1, 4, 38,
		},
		{
			"frames436and438",
			"dd848000000100010000000002673100001c000102673100001c00010000001e0010fe80000000000000b871eca9c39b9fed",
			"fe80::b871:eca9:c39b:9fed", "fe80000000000000b871eca9c39b9fed", 28, 16, 50,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			header, err := llmnr.DecodeHeader(data)
			if err != nil {
				t.Fatal(err)
			}
			if !header.QR || header.QDCount != 1 || header.ANCount != 1 {
				t.Fatalf("unexpected header: %+v", header)
			}
			question, offset, err := llmnr.DecodeQuestion(data, llmnr.HeaderSize)
			if err != nil {
				t.Fatal(err)
			}
			if question.Name != "g1" || question.Type != tc.wantType || question.Class != 1 || offset != 20 {
				t.Fatalf("unexpected question: %+v, offset %d", question, offset)
			}
			record, next, err := llmnr.DecodeResourceRecord(data, offset)
			if err != nil {
				t.Fatal(err)
			}
			if record.Name != "g1" || record.Type != tc.wantType || record.Class != 1 || record.TTL != 30 || record.RDLength != tc.length {
				t.Fatalf("unexpected record: %+v", record)
			}
			if record.Address.String() != tc.address {
				t.Errorf("address = %s, want %s", record.Address, tc.address)
			}
			if hex.EncodeToString(record.RData) != tc.rdata {
				t.Errorf("RDATA = %x, want %s", record.RData, tc.rdata)
			}
			if next != tc.end || next != len(data) {
				t.Errorf("next = %d, want %d (end of payload)", next, tc.end)
			}
		})
	}
}
