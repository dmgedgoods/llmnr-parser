package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	llmnr "github.com/dmgedgoods/llmnr-parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	path := flag.String("pcap", "llmnr_v2.pcap", "PCAP file to inspect")
	flag.Parse()
	if err := run(*path, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path string, output, diagnostics io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		return err
	}
	llmnr.RegisterUDP()
	encoder := json.NewEncoder(output)
	frames, decoded, failures, otherErrors := 0, 0, 0, 0
	for {
		data, _, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read frame %d: %w", frames+1, err)
		}
		frames++
		packet := gopacket.NewPacket(data, r.LinkType(), gopacket.Default)
		if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok && (tcp.SrcPort == 5355 || tcp.DstPort == 5355) {
			failures++
			fmt.Fprintf(diagnostics, "frame %d: TCP LLMNR is not supported yet\n", frames)
			continue
		}
		udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok || (udp.SrcPort != 5355 && udp.DstPort != 5355) {
			if packet.ErrorLayer() != nil {
				otherErrors++
			}
			continue
		}
		if problem := packet.ErrorLayer(); problem != nil {
			failures++
			fmt.Fprintf(diagnostics, "frame %d: %v\n", frames, problem.Error())
			continue
		}
		layer, ok := packet.Layer(llmnr.LayerTypeLLMNR).(*llmnr.Layer)
		if !ok {
			failures++
			fmt.Fprintf(diagnostics, "frame %d: UDP port 5355 did not select the LLMNR decoder\n", frames)
			continue
		}
		src, dst := "", ""
		if network := packet.NetworkLayer(); network != nil {
			src, dst = network.NetworkFlow().Src().String(), network.NetworkFlow().Dst().String()
		}
		entry := struct {
			Frame                       int
			Source, Destination         string
			SourcePort, DestinationPort uint16
			Message                     llmnr.Message
		}{frames, src, dst, uint16(udp.SrcPort), uint16(udp.DstPort), layer.Message}
		if err := encoder.Encode(entry); err != nil {
			return err
		}
		decoded++
	}
	fmt.Fprintf(diagnostics, "frames=%d llmnr=%d failures=%d other_decode_errors=%d\n", frames, decoded, failures, otherErrors)
	if failures > 0 {
		return fmt.Errorf("%d port-5355 packets could not be decoded", failures)
	}
	return nil
}
