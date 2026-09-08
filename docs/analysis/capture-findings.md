# PCAP assessment

Analyzed only `llmnr_v2.pcap`, as requested. The user states the PCAPNG is the same capture in another format; it was not analyzed or compared.

- Tool: installed TShark 4.6.8.0.
- Input size: 98,803 bytes.
- SHA256: `0C52865F75D29BA036FC9E799D2B4E8EEBD40D48110B28C5F5DFCA5CB7FA2E16`.
- 610 Ethernet frames total; 8 LLMNR frames, split evenly between IPv4 and IPv6.
- Frames 429/430: A query for `g1`, ID `0xe221`, source port 54573.
- Frames 431/432: AAAA query for `g1`, ID `0xdd84`, source port 59261.
- Frames 435/437: A response containing `192.168.1.177`.
- Frames 436/438: AAAA response containing `fe80::b871:eca9:c39b:9fed`.
- Queries: destination UDP port 5355, multicast destinations `224.0.0.252` and `ff02::1:3`.
- Responses: source UDP port 5355, unicast back to the requester.
- Every message has one IN-class question. Responses have one answer, TTL 30 seconds. Authority and additional counts are zero.
- Flags: queries `0x0000`, responses `0x8000`; conflict, truncation, tentative, opcode and response code bits are zero.
- UDP payload lengths: queries 20 bytes, A responses 38 bytes, AAAA responses 50 bytes.
- Payload bytes show literal `02 67 31 00` names in questions and answers, with no compression pointers.
- All port-5355 frames are the same eight LLMNR frames; no TCP port-5355 frames were found.
- `_ws.malformed` matched no frames in the capture. This is a dissector observation, not proof of exhaustive protocol validity. Checksums in the detailed output were unverified.

## Implementation implications

Decode both IPv4 and IPv6 UDP traffic and inspect both source and destination port so responses are included. Keep the record type independent of the transport address family: both A and AAAA are present over each family. Compare all eight frames against the saved TShark fields, including transaction IDs, counts, questions, TTLs and answers.

The supplied capture cannot demonstrate handling of compressed names, malformed or truncated messages, nonzero special flags, multiple records, or TCP. Separate constructed tests are needed for supported behavior outside this baseline. No parser has been implemented or validated yet.

## Reproduction

Run from the repository root in PowerShell:

```powershell
tshark -r llmnr_v2.pcap -q -z io,phs
tshark -n -r llmnr_v2.pcap -Y llmnr -V
tshark -r llmnr_v2.pcap -Y 'udp.port == 5355 || tcp.port == 5355' -T fields -e frame.number -e _ws.col.Protocol -e _ws.col.Info
tshark -r llmnr_v2.pcap -Y '_ws.malformed' -T fields -e frame.number -e _ws.col.Info
tshark -n -r llmnr_v2.pcap -Y llmnr -T fields -E header=y -e frame.number -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst -e udp.srcport -e udp.dstport -e dns.id -e dns.flags -e dns.count.queries -e dns.count.answers -e dns.qry.name -e dns.qry.type -e dns.resp.ttl -e dns.a -e dns.aaaa -e udp.payload
Get-FileHash llmnr_v2.pcap -Algorithm SHA256
```

TShark exposes these LLMNR message fields using `dns.*` field names. Saved evidence: `llmnr-tshark-detail.txt` and `llmnr-tshark-fields.tsv` in this directory.
