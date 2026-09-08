# Synthetic edge-case capture

Regenerate the deterministic five-packet Ethernet/UDP PCAP from the repository root:

```powershell
go run ./cmd/genfixtures
go test -v ./cmd/llmnr
go run ./cmd/llmnr -pcap testdata/edge-cases.pcap
```

The generator writes only testdata/edge-cases.pcap. Hand-authored LLMNR bytes are wrapped with gopacket serialization and calculated lengths/checksums; timestamps are fixed. Nothing is transmitted. These are isolated parsing fixtures, not a complete resolver conversation.

SHA256: `88EA7A40F2B10B9BF8CC1A7AF0929F894FC1FF8853207DF0D023E2C495E557E7`.

| Frame | IP | ID | Expected result |
|---|---|---|---|
| 1 | IPv4 | 0x1001 | Negative AAAA response for g1, no answers, one SOA authority record; TTL and MINIMUM 15 |
| 2 | IPv6 | 0x1002 | A query with an OPT additional record, UDP payload size 1232, no options |
| 3 | IPv4 | 0x1003 | Conflict notification (C=1) with additional A record 192.0.2.2 |
| 4 | IPv6 | 0x1004 | Malformed A response: RDLENGTH=4 but only three bytes remain |
| 5 | IPv6 | 0x1005 | Valid AAAA response fe80::2, TTL 30; decode despite preceding error |

Expected JSON output contains frames **1, 2, 3, 5**. Stderr identifies frame 4 and reports `frames=5 llmnr=4 failures=1 other_decode_errors=0`. Exit code **1** is intentional. Original capture execution exits **0**. SOA contents are preserved byte-for-byte, not interpreted; OPT metadata remains in raw CLASS/TTL fields.

Independent verification:

```powershell
tshark -n -r testdata/edge-cases.pcap -o ip.check_checksum:TRUE -o udp.check_checksum:TRUE -T fields -E header=y -e frame.number -e _ws.col.Info -e ip.checksum.status -e udp.checksum.status
```

TShark 4.6.8 flags only frame 4 malformed. All UDP and both IPv4 checksums report status 1 (good). Only LLMNR is deliberately malformed; transport lengths are intact. Saved evidence is under docs/analysis/: synthetic-tshark.tsv, synthetic-tshark-detail.txt, synthetic-parser-output.jsonl, synthetic-parser-summary.txt and exit-codes.txt.
