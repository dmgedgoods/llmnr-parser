# LLMNR parser assessment

See [assessment findings](docs/assessment-summary.md) for final results and [synthetic dataset](testdata/README.md) for the five-packet edge-case capture and expected failure behavior.

An incremental Go LLMNR decoder with a custom gopacket application layer and an offline PCAP command.

```powershell
go test ./...
go vet ./...
go run ./cmd/llmnr -pcap llmnr_v2.pcap
```

The command writes one JSON object per LLMNR packet to stdout and a summary to stderr. Record RData is base64 in JSON; addresses are readable strings. Empty sections currently encode as null. Read errors and undecodable port-5355 traffic produce a nonzero exit. Unrelated application decode errors are counted separately.

Verified with Go 1.27.0 on Windows. The module declares Go 1.22 and pins the original github.com/google/gopacket v1.1.19. Dependencies are in go.mod/go.sum. PCAP reading uses pcapgo and requires no live-capture device or libpcap installation.

## Observed result

```text
frames=610 llmnr=8 failures=0 other_decode_errors=0
```

Frames 429, 430, 431, 432, 435, 436, 437, 438 decode with the expected IDs, questions, addresses and TTLs. See [saved JSON](docs/analysis/parser-output.jsonl), [summary](docs/analysis/parser-summary.txt), and [TShark baseline](docs/analysis/capture-findings.md). Only llmnr_v2.pcap was assessed; the user identifies the PCAPNG as another encoding of the same capture.

## Using the layer

Call llmnr.RegisterUDP() before packet decoding starts, then use gopacket.NewPacket with the capture's link type. Retrieve packet.Layer(llmnr.LayerTypeLLMNR) as *llmnr.Layer. Errors appear through packet.ErrorLayer(). RegisterUDP changes gopacket's global port-5355 mapping; layer ID 2001 is reserved for this application. The lower-level DecodeMessage API accepts an LLMNR payload directly.

## Current scope

- Header, questions and all three resource-record sections.
- Uncompressed names; IN A/AAAA address decoding; raw data for other records.
- Bounds checks, section-count iteration and trailing-byte rejection.
- Offline PCAP decoding of UDP over IPv4/IPv6 through gopacket.

Pending: name compression, typed SOA/OPT interpretation, TCP framing/reassembly, IP-fragment reassembly and broader protocol validation. The CLI flags visible TCP port-5355 traffic as unsupported. No checksum validation or resolver/cache state machine is implemented. gopacket chooses UDP decoders by destination port before source port, so a response to another registered application port may not select LLMNR; the command reports that failure. The sample does not exercise this case. This is not a claim of complete RFC conformance.

## Assessment record

[AI communications log](docs/ai/session-log.md) contains prompts and visible responses from the user-designated starting point, with summarized tool activity. [Analysis documents](docs/analysis/) preserve findings and incremental decisions; older entries describe the implementation as it stood then. Synthetic payload fixtures live in the test files. The user is recording the session separately; this repository does not create the screen recording.
