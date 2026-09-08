# Answer record decoding

References: [RFC 1035 section 4.1.3](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.3) for resource records and IN A data, and [RFC 3596 section 2.2](https://www.rfc-editor.org/rfc/rfc3596.html#section-2.2) for AAAA data.

Use ResourceRecord and DecodeResourceRecord because answer, authority and additional sections share the same record format. The function reads one record, leaving section-count iteration to the forthcoming message decoder. It reuses the existing name decoder; compression remains explicitly unsupported.

After the name, read two-byte type/class, four-byte TTL, and two-byte RDLENGTH in network order. Validate the fixed fields and declared data length before accessing bytes. Return the original offset with an empty record on errors. Preserve TTL as its raw unsigned wire value; no cache policy is applied.

Interpret addresses only for IN-class A (4 bytes) and AAAA (16 bytes). Reject incorrect lengths for these supported types. Other types/classes retain opaque RDATA. netip.Addr provides a value representation that distinguishes IPv4 from IPv6. Copy raw data so it survives input-buffer reuse; preserve RDLENGTH for comparison with Wireshark. Unknown record contents are not semantically validated.

Validation: literal captured response payloads from frames 435/437 and 436/438 pass through header, question, and record decoding. Expected names, types, classes, TTLs, lengths, raw bytes, addresses and final offsets match the saved TShark baseline. The payloads within each pair are identical. `go test ./...` and `go vet ./...` passed. Per the user's instruction, additional synthetic record tests are deferred; new error branches are not yet covered by those tests. Existing header/question tests remain. Full PCAP reading and gopacket integration are still pending.
