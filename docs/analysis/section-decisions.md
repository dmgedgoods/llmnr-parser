# Authority and additional slices

Implemented Message.Authorities and Message.Additionals using the existing resource-record decoder. Decode in wire order: questions, answers, authorities, additionals. Counts and byte offsets remain independent for each section. Never merge records into Answers merely because they contain an address. All record sections get the same bounds checks and owned RDATA copies.

This supersedes the earlier unsupported-section behavior described in the historical session log and authority-additional review. SOA fields are preserved as raw RDATA, not yet interpreted or internally validated. OPT's raw CLASS and TTL fields are preserved without treating them as an ordinary class or cache lifetime; comments now make this distinction explicit. Cache policy and responder behavior remain outside this structural decoder.

Added sections_test.go with manually authored synthetic payloads for a negative response with and without SOA, an empty-option OPT query, a conflict notification with an additional A record, and a structural mixed-section fixture with two additional records. Checks cover section separation, ordering, raw data and metadata preservation, buffer reuse, every truncated prefix within authority/additional records, and counts claiming missing second entries. The mixed fixture is intended to test structural decoding, not prescribe a conforming responder's output. Existing missing-section tests now expect missing-record errors rather than unsupported errors.

Validation: go test ./... and go vet ./... passed. Full transport/PCAP integration, name compression and typed SOA/OPT interpretation remain pending.
