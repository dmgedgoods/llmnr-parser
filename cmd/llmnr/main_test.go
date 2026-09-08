package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	llmnr "github.com/dmgedgoods/llmnr-parser"
)

func TestSyntheticPCAP(t *testing.T) {
	var output, diagnostics bytes.Buffer
	err := run("../../testdata/edge-cases.pcap", &output, &diagnostics)
	if err == nil || !strings.Contains(err.Error(), "1 port-5355 packets") {
		t.Fatalf("want one failure, got %v", err)
	}
	if !strings.Contains(diagnostics.String(), "frame 4:") || !strings.Contains(diagnostics.String(), "short record data") || !strings.Contains(diagnostics.String(), "frames=5 llmnr=4 failures=1 other_decode_errors=0") {
		t.Fatalf("diagnostics: %s", &diagnostics)
	}
	decoder := json.NewDecoder(&output)
	var frames []int
	for {
		var row struct {
			Frame   int
			Message llmnr.Message
		}
		if err := decoder.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, row.Frame)
		m := row.Message
		if m.Header.ID != uint16(0x1000+row.Frame) || len(m.Questions) != 1 {
			t.Fatalf("frame %d: wrong header/questions", row.Frame)
		}
		switch row.Frame {
		case 1:
			if !m.Header.QR || m.Header.RCode != 0 || len(m.Answers) != 0 || len(m.Authorities) != 1 || len(m.Additionals) != 0 {
				t.Fatalf("negative response: %+v", m)
			}
			a := m.Authorities[0]
			if a.Type != 6 || a.TTL != 15 || a.RDLength != 25 || hex.EncodeToString(a.RData) != "0267310000000000010000003c0000001e000000780000000f" {
				t.Fatalf("SOA: %+v", a)
			}
		case 2:
			if m.Header.QR || len(m.Answers) != 0 || len(m.Authorities) != 0 || len(m.Additionals) != 1 {
				t.Fatalf("OPT sections: %+v", m)
			}
			a := m.Additionals[0]
			if a.Type != 41 || a.Name != "." || a.Class != 1232 || a.TTL != 0 || len(a.RData) != 0 {
				t.Fatalf("OPT: %+v", a)
			}
		case 3:
			if m.Header.QR || !m.Header.Conflict || len(m.Answers) != 0 || len(m.Authorities) != 0 || len(m.Additionals) != 1 || m.Additionals[0].Address.String() != "192.0.2.2" {
				t.Fatalf("conflict: %+v", m)
			}
		case 5:
			if !m.Header.QR || len(m.Answers) != 1 || m.Answers[0].Address.String() != "fe80::2" || m.Answers[0].TTL != 30 {
				t.Fatalf("response after malformed frame: %+v", m)
			}
		default:
			t.Fatalf("unexpected frame %d", row.Frame)
		}
	}
	if !reflect.DeepEqual(frames, []int{1, 2, 3, 5}) {
		t.Fatalf("output frames: %v", frames)
	}
}

func TestOriginalPCAPCommand(t *testing.T) {
	var output, diagnostics bytes.Buffer
	if err := run("../../llmnr_v2.pcap", &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if bytes.Count(output.Bytes(), []byte{'\n'}) != 8 || diagnostics.String() != "frames=610 llmnr=8 failures=0 other_decode_errors=0\n" {
		t.Fatalf("unexpected command result: %s", &diagnostics)
	}
}
