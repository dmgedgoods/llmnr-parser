# Assessment findings and validation

## Outcome

Implemented a custom gopacket LLMNR application layer and offline PCAP command. The supplied PCAP produces eight LLMNR messages from 610 frames with zero decoding errors. The five-packet synthetic PCAP produces four messages and one intentional error, continues decoding after the error, and exits with status 1. Original capture execution exits with status 0.

## Decisions

- Decode LLMNR flags explicitly, preserving Conflict/Tentative instead of DNS AA/RD meanings.
- Separate header, question, record and message decoding for reviewable offsets and bounds checks; the gopacket layer reuses this implementation.
- Iterate section counts in wire order, preserve section boundaries and return no partial message after errors.
- Preserve unknown record data and raw flag values. Copy record data to survive capture-buffer reuse.
- Expand authority/additional support after RFC review identified valid negative responses and metadata absent from the capture.
- Use pcapgo for offline reading and pin the original gopacket dependency.

Detailed rationale and primary-source references are in [analysis](analysis/). Earlier documents and the session log describe scope at the time each step was implemented.

## Validation

Matched all eight original LLMNR packets against independent TShark output: frame numbers, endpoints, ports, IDs, question names/types, answer addresses and TTLs. Input hash and baseline are in analysis/capture-findings.md. Actual output is in analysis/parser-output.jsonl and parser-summary.txt.

The [synthetic dataset](../testdata/README.md) exercises SOA authority data, OPT metadata, conflict notification, malformed answer data and successful decoding after that error. TShark agrees on the malformed frame and validates transport checksums. Expected fields are manually authored independently of our decoder.

`go test ./...`, `go vet ./...`, and command build passed on Go 1.27.0 windows/amd64. Tests cover captured messages, flags, names and bounds, short input, counts, section boundaries, opaque data, buffer reuse, actual-PCAP gopacket dispatch and synthetic-PCAP command behavior. Actual executable exit codes were verified. This validates the stated cases, not exhaustive protocol correctness. Fuzzing was excluded by agreement.

## Limitations

Compressed names, TCP and reassembly remain unsupported. SOA/OPT and other non-address contents are preserved but not fully interpreted or validated. This is a structural decoder, not a resolver, cache, authentication verifier or complete RFC validator. gopacket's destination-port-first UDP dispatch can prevent LLMNR selection if another application owns that destination port; the command reports that failure. The parser does not validate checksums; synthetic checksums were checked externally. These limitations do not affect the eight supplied packets.

## Deliverables

- Code, dependency pins and tests: root and cmd/.
- Datasets: unchanged llmnr_v2.pcap and generated testdata/edge-cases.pcap; generator in cmd/genfixtures/.
- Findings, decisions and evidence: this document and analysis/.
- AI usage: [communications log](ai/session-log.md), containing user prompts, visible responses and summarized tool activity/approval prompts from the designated session boundary. AI assisted with research, code, fixtures, checks and documentation; the user directed and reviewed each chunk. This curated log is not a raw tool-event export. Earlier workflow-preparation exchanges precede the requested logging boundary.
- Unedited screen recording: operated by the user separately. The assistant has not inspected or packaged it; include it with the submission after ending the recording.
