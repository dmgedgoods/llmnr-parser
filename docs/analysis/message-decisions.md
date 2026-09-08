# Combining sections and synthetic data

DecodeMessage takes a complete LLMNR payload (starting at ID, excluding UDP/IP/Ethernet headers). It returns Header, Questions and Answers. Header counts determine iteration; each decoder returns the next offset. Allocate entries only after successful decoding rather than preallocating from packet-supplied counts. Errors name the section, one-based entry number and byte offset; no partial message is returned. Reject unconsumed bytes so counts cannot hide leftover data.

Scope expanded after reviewing negative responses: Authorities and Additionals now preserve their records separately, following NSCOUNT and ARCOUNT. All three record sections share one ordered decoding loop and section-specific errors. SOA and OPT data remain opaque; typed SOA fields and EDNS metadata interpretation are not implemented. Compression remains explicitly unsupported. This is structural decoding, not full protocol validation: it does not enforce resolver rules such as exactly one question, supported opcodes, or query-specific count/flag restrictions.

## Synthetic payload example

The multiple-answer test uses manually authored bytes rather than a production encoder, so shared encoder/decoder mistakes cannot make this check pass by agreement:

```text
1234 8000 0001 0002 0000 0000                 header: response, 1 question, 2 answers
02673100 0001 0001                            question: g1, A, IN
02673100 0001 0001 0000001e 0004 c0000201       answer: 192.0.2.1, TTL 30
02673100 0001 0001 0000003c 0004 c0000202       answer: 192.0.2.2, TTL 60
```

Fixtures live in message_test.go. These are message payloads, not complete Ethernet/IP/UDP packets or a synthetic PCAP. Generated full packets remain future integration work. The synthetic tests cover ordered multiple answers and data ownership, opaque unknown record types, missing entries, short fixed fields and RDATA, wrong A/AAAA lengths, trailing bytes and explicit unsupported-feature errors. Every shorter prefix of the captured A response is also rejected without returning a partial message.

Capture-based message tests cover the four distinct LLMNR payloads that occur across the eight captured frames; this does not yet exercise capture-file reading or transport decoding.

Validation: `go test -v ./...` and `go vet ./...` passed. Run only synthetic cases with `go test -v -run Synthetic ./...`. The test cases and implementation were added together; this was not a red-green TDD sequence. No existing capture files were modified.
