// genfixtures writes a deterministic five-packet PCAP for the assessment.
package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	if err := generate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate() error {
	// Payloads are hand-authored, independently of the production decoder.
	const soa = "02673100 0006 0001 0000000f 0019 02673100 00 00000001 0000003c 0000001e 00000078 0000000f"
	fixtures := []struct {
		ipv6, response bool
		wire           string
	}{
		{false, true, "1001 8000 0001 0000 0001 0000 02673100 001c 0001 " + soa},
		{true, false, "1002 0000 0001 0000 0000 0001 02673100 0001 0001 00 0029 04d0 00000000 0000"},
		{false, false, "1003 0400 0001 0000 0000 0001 02673100 0001 0001 02673100 0001 0001 0000001e 0004 c0000202"},
		// The transport contains all its bytes, but RDLENGTH claims four
		// bytes while only three remain. Only the LLMNR payload is malformed.
		{true, true, "1004 8000 0001 0001 0000 0000 02673100 0001 0001 02673100 0001 0001 0000001e 0004 c00002"},
		{true, true, "1005 8000 0001 0001 0000 0000 02673100 001c 0001 02673100 001c 0001 0000001e 0010 fe800000000000000000000000000002"},
	}
	if err := os.MkdirAll("testdata", 0755); err != nil {
		return err
	}
	f, err := os.Create("testdata/edge-cases.pcap")
	if err != nil {
		return err
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return err
	}
	for i, fixture := range fixtures {
		payload, err := hex.DecodeString(strings.Join(strings.Fields(fixture.wire), ""))
		if err != nil {
			return err
		}
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
		udp := &layers.UDP{SrcPort: 55000, DstPort: 5355}
		if fixture.response {
			udp.SrcPort, udp.DstPort = 5355, 55000
		}
		var network gopacket.SerializableLayer
		if fixture.ipv6 {
			eth.EthernetType = layers.EthernetTypeIPv6
			ip := &layers.IPv6{Version: 6, HopLimit: 255, NextHeader: layers.IPProtocolUDP, SrcIP: net.ParseIP("fe80::1"), DstIP: net.ParseIP("ff02::1:3")}
			eth.DstMAC = net.HardwareAddr{0x33, 0x33, 0, 1, 0, 3}
			if fixture.response {
				ip.SrcIP, ip.DstIP = net.ParseIP("fe80::2"), net.ParseIP("fe80::1")
				eth.SrcMAC, eth.DstMAC = net.HardwareAddr{2, 0, 0, 0, 0, 2}, net.HardwareAddr{2, 0, 0, 0, 0, 1}
			}
			if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
				return err
			}
			network = ip
		} else {
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 255, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(224, 0, 0, 252)}
			eth.DstMAC = net.HardwareAddr{1, 0, 0x5e, 0, 0, 0xfc}
			if fixture.response {
				ip.SrcIP, ip.DstIP = net.IPv4(192, 0, 2, 2), net.IPv4(192, 0, 2, 1)
				eth.SrcMAC, eth.DstMAC = net.HardwareAddr{2, 0, 0, 0, 0, 2}, net.HardwareAddr{2, 0, 0, 0, 0, 1}
			}
			if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
				return err
			}
			network = ip
		}
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, network, udp, gopacket.Payload(payload)); err != nil {
			return err
		}
		packet := buffer.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000+int64(i), 0).UTC(), CaptureLength: len(packet), Length: len(packet)}, packet); err != nil {
			return err
		}
	}
	return f.Sync()
}
