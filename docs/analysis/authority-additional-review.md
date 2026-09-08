# Authority and additional section review

Checked RFC 4795 sections 2.3 and 2.9 after the user identified a gap in the capture-driven scope.

The current blanket rejection of nonzero NSCOUNT/ARCOUNT excludes legitimate messages. Recommended next implementation: preserve each section separately, add typed SOA decoding, retain unknown records, and test negative responses with and without SOA, EDNS0 and conflict notifications. These are proposed changes, not implemented behavior. Resolver/cache rules should be documented separately from structural decoding.

Sources and detailed findings are recorded in session-log.md, exchange 31. In particular, absence of SOA should not be made a structural error. Additional records should not be merged into Answers, and query-specific restrictions should not be applied indiscriminately to responses.

One related test caveat: RFC 4795 section 2.8 requires matching TTLs within an RRset. The existing synthetic multiple-A-answer fixture intentionally has different TTLs to expose byte-offset mistakes. It is a structural-decoding fixture, not a fully conforming responder example; retain that distinction when generating protocol-valid synthetic PCAPs.

No code or tests were changed during this research check.
