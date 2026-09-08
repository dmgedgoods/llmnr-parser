package llmnr_test

import (
	"io"
	"os"
	"reflect"
	"testing"

	llmnr "github.com/dmgedgoods/llmnr-parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestGopacketCapture(t *testing.T) {
	f, err := os.Open("llmnr_v2.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	llmnr.RegisterUDP()
	wantFrames := []int{429, 430, 431, 432, 435, 436, 437, 438}
	var gotFrames []int
	frames, ipv4, ipv6 := 0, 0, 0
	for {
		data, _, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		frames++
		p := gopacket.NewPacket(data, r.LinkType(), gopacket.Default)
		udp, ok := p.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok || (udp.SrcPort != 5355 && udp.DstPort != 5355) {
			continue
		}
		if problem := p.ErrorLayer(); problem != nil {
			t.Fatalf("frame %d: %v", frames, problem.Error())
		}
		l, ok := p.Layer(llmnr.LayerTypeLLMNR).(*llmnr.Layer)
		if !ok {
			t.Fatalf("frame %d: missing LLMNR layer", frames)
		}
		if p.ApplicationLayer() != l {
			t.Fatal("LLMNR not exposed as application layer")
		}
		gotFrames = append(gotFrames, frames)
		if p.Layer(layers.LayerTypeIPv4) != nil {
			ipv4++
		}
		if p.Layer(layers.LayerTypeIPv6) != nil {
			ipv6++
		}
		wantID, wantType := uint16(0xe221), uint16(1)
		if frames == 431 || frames == 432 || frames == 436 || frames == 438 {
			wantID, wantType = 0xdd84, 28
		}
		if l.Header.ID != wantID || len(l.Questions) != 1 || l.Questions[0] != (llmnr.Question{Name: "g1", Type: wantType, Class: 1}) {
			t.Fatalf("frame %d: unexpected message %+v", frames, l.Message)
		}
		if l.Header.QR != (frames >= 435) || len(l.Authorities) != 0 || len(l.Additionals) != 0 {
			t.Fatalf("frame %d: wrong flags/sections", frames)
		}
		if frames >= 435 {
			wantAddress := "192.168.1.177"
			if wantType == 28 {
				wantAddress = "fe80::b871:eca9:c39b:9fed"
			}
			if len(l.Answers) != 1 || l.Answers[0].Address.String() != wantAddress || l.Answers[0].TTL != 30 {
				t.Fatalf("frame %d: wrong answers %+v", frames, l.Answers)
			}
		} else if len(l.Answers) != 0 {
			t.Fatalf("frame %d: query has answers", frames)
		}
	}
	if frames != 610 || ipv4 != 4 || ipv6 != 4 || !reflect.DeepEqual(gotFrames, wantFrames) {
		t.Fatalf("frames=%d ipv4=%d ipv6=%d LLMNR frames=%v", frames, ipv4, ipv6, gotFrames)
	}
}

func TestGopacketMalformedLLMNR(t *testing.T) {
	p := gopacket.NewPacket([]byte{0x12}, llmnr.LayerTypeLLMNR, gopacket.Default)
	if p.ErrorLayer() == nil || p.Layer(llmnr.LayerTypeLLMNR) != nil {
		t.Fatal("malformed data did not become a decode error")
	}
	if !p.Metadata().Truncated {
		t.Fatal("short header not marked truncated")
	}
}

func TestGopacketLayerReuseClearsMessage(t *testing.T) {
	l := &llmnr.Layer{}
	data := payloadHex(t, "e221000000010000000000000267310000010001")
	if err := l.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if err := l.DecodeFromBytes(nil, gopacket.NilDecodeFeedback); err == nil {
		t.Fatal("short input accepted")
	}
	if len(l.Questions) != 0 || l.Header.ID != 0 || len(l.Contents) != 0 {
		t.Fatal("stale message after failure")
	}
}
