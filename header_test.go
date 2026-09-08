package llmnr_test

import (
	"encoding/hex"
	"testing"

	llmnr "github.com/dmgedgoods/llmnr-parser"
)

func TestDecodeHeaderCapture(t *testing.T) {
	// Literal UDP payloads independently decoded by TShark; see docs/analysis.
	for _, tc := range []struct {
		name, payload string
		want          llmnr.Header
	}{
		{"frame429", "e221000000010000000000000267310000010001", llmnr.Header{ID: 0xe221, QDCount: 1}},
		{"frame435", "e22180000001000100000000026731000001000102673100000100010000001e0004c0a801b1", llmnr.Header{ID: 0xe221, QR: true, QDCount: 1, ANCount: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			got, err := llmnr.DecodeHeader(data)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestDecodeHeaderShortInput(t *testing.T) {
	for n := 0; n < llmnr.HeaderSize; n++ {
		if _, err := llmnr.DecodeHeader(make([]byte, n)); err == nil {
			t.Errorf("length %d: expected an error", n)
		}
	}
}

func TestDecodeHeaderFlagPositions(t *testing.T) {
	// Each literal sets one field independently, following RFC 4795's diagram.
	for _, tc := range []struct {
		name   string
		hi, lo byte
		want   llmnr.Header
	}{
		{"QR", 0x80, 0, llmnr.Header{QR: true}},
		{"opcode", 0x78, 0, llmnr.Header{Opcode: 15}},
		{"conflict", 0x04, 0, llmnr.Header{Conflict: true}},
		{"truncated", 0x02, 0, llmnr.Header{Truncated: true}},
		{"tentative", 0x01, 0, llmnr.Header{Tentative: true}},
		{"reserved", 0, 0xf0, llmnr.Header{Reserved: 15}},
		{"rcode", 0, 0x0f, llmnr.Header{RCode: 15}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, llmnr.HeaderSize)
			data[2], data[3] = tc.hi, tc.lo
			got, err := llmnr.DecodeHeader(data)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestDecodeHeaderByteOrderAndCounts(t *testing.T) {
	// Deliberately distinct values expose swapped bytes and section offsets.
	data := []byte{0x12, 0x34, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	want := llmnr.Header{ID: 0x1234, QDCount: 0x0102, ANCount: 0x0304, NSCount: 0x0506, ARCount: 0x0708}
	got, err := llmnr.DecodeHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
