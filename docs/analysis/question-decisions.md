# Question decoding

Reference: [RFC 1035 sections 3.1 and 4.1.2](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.2); LLMNR adopts the DNS message format via RFC 4795 section 2.1.

`DecodeQuestion(data, offset)` takes the complete message and an offset, returning one question and the next offset. This lets later section parsing advance through the message without fixed question lengths. It does not validate the header or iterate QDCOUNT; that belongs to message-level integration.

This chunk supports uncompressed names, as seen in the capture. Compression is explicitly rejected as unsupported, not claimed to be invalid LLMNR. Add pointer handling separately before claiming general name support. Other nonzero label-prefix encodings also return errors.

Preserve case. Render the root as a dot; omit trailing dots on other names. Escape embedded dots, backslashes and non-printable bytes using decimal escapes, preserving label boundaries and arbitrary bytes without imposing hostname syntax. Keep type/class as numeric uint16 values so unknown codes remain inspectable.

Check offsets before indexing, label bounds before slicing, total encoded name length, and availability of both trailing fields. Failed calls return the original offset and an empty question, allowing callers to avoid advancing on failure.

Tests use literal TShark payloads from frames 429, 431 and 435. Additional constructed fixtures check root/multiple labels, case and byte preservation, unknown type/class values, every truncated prefix of the sample question, invalid offsets, unsupported compression/encodings and length boundaries. `go test ./...` and `go vet ./...` passed. No end-to-end PCAP parsing or gopacket integration is claimed yet.
