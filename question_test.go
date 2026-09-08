package llmnr_test

import (
	"encoding/hex"
	"strings"
	"testing"

	llmnr "github.com/dmgedgoods/llmnr-parser"
)

func TestDecodeQuestionCapture(t *testing.T) {
	for _, tc := range []struct {
		name, payload string
		wantType      uint16
	}{
		{"frame429", "e221000000010000000000000267310000010001", 1},
		{"frame431", "dd840000000100000000000002673100001c0001", 28},
		{"frame435", "e22180000001000100000000026731000001000102673100000100010000001e0004c0a801b1", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			got, next, err := llmnr.DecodeQuestion(data, llmnr.HeaderSize)
			if err != nil {
				t.Fatal(err)
			}
			want := llmnr.Question{Name: "g1", Type: tc.wantType, Class: 1}
			if got != want || next != 20 {
				t.Fatalf("got %+v, next %d; want %+v, next 20", got, next, want)
			}
		})
	}
}

func TestDecodeQuestionNames(t *testing.T) {
	for _, tc := range []struct{ name, wire, want string }{
		{"multiple labels and case", "\x02G1\x05local\x00", "G1.local"},
		{"root", "\x00", "."},
		{"literal dot", "\x03a.b\x00", `a\046b`},
		{"binary bytes", "\x03\x00\\\xff\x00", `\000\092\255`},
		{"maximum label", "\x3f" + strings.Repeat("a", 63) + "\x00", strings.Repeat("a", 63)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.wire + "\x12\x34\xab\xcd")
			got, next, err := llmnr.DecodeQuestion(data, 0)
			if err != nil {
				t.Fatal(err)
			}
			want := llmnr.Question{Name: tc.want, Type: 0x1234, Class: 0xabcd}
			if got != want || next != len(data) {
				t.Fatalf("got %+v, next %d; want %+v, next %d", got, next, want, len(data))
			}
		})
	}
}

func TestDecodeQuestionRejectsIncompleteInput(t *testing.T) {
	data := []byte{2, 'g', '1', 0, 0, 1, 0, 1}
	for n := 0; n < len(data); n++ {
		if _, _, err := llmnr.DecodeQuestion(data[:n], 0); err == nil {
			t.Errorf("length %d: expected error", n)
		}
	}
	for _, offset := range []int{-1, len(data), len(data) + 1, int(^uint(0) >> 1)} {
		if _, next, err := llmnr.DecodeQuestion(data, offset); err == nil || next != offset {
			t.Errorf("offset %d: next=%d, err=%v", offset, next, err)
		}
	}
}

func TestDecodeQuestionRejectsUnsupportedNames(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"compression", []byte{0xc0, 0x0c, 0, 1, 0, 1}, "compression not supported yet"},
		{"reserved 01", []byte{0x40, 0, 0, 1, 0, 1}, "unsupported label encoding"},
		{"reserved 10", []byte{0x80, 0, 0, 1, 0, 1}, "unsupported label encoding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := llmnr.DecodeQuestion(tc.data, 0); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestDecodeQuestionNameLengthBoundary(t *testing.T) {
	// Three 63-byte labels plus one 61-byte label and the root occupy 255 bytes.
	prefix := strings.Repeat("\x3f"+strings.Repeat("a", 63), 3)
	valid := []byte(prefix + "\x3d" + strings.Repeat("b", 61) + "\x00\x00\x01\x00\x01")
	if _, next, err := llmnr.DecodeQuestion(valid, 0); err != nil || next != 259 {
		t.Fatalf("maximum name: next=%d, err=%v", next, err)
	}
	invalid := []byte(prefix + "\x3e" + strings.Repeat("b", 62) + "\x00\x00\x01\x00\x01")
	if _, _, err := llmnr.DecodeQuestion(invalid, 0); err == nil {
		t.Fatal("accepted a 256-byte name")
	}
}
