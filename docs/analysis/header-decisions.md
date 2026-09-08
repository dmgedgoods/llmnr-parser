# Header decoding decisions

## Conflict and tentative semantics

C and T both participate in name uniqueness handling but are decoded independently. In queries, C reports multiple responses; responders do not answer such queries but may initiate uniqueness verification. In responses, C indicates whether the name is considered non-unique. T in a response indicates that an authoritative responder has not yet verified uniqueness; T in a query is ignored. Tentative responses are discarded during ordinary resolution, while a tentative response to a uniqueness query signals a conflict to resolve. These rules come from RFC 4795 section 2.1.1. The parser reports flags; it does not implement a resolver's conflict-handling state machine. All eight captured LLMNR messages have C and T clear.

Source: [RFC 4795 section 2.1.1](https://www.rfc-editor.org/rfc/rfc4795.html#section-2.1.1), checked during implementation.

The header is 12 bytes: six network-order 16-bit words containing ID, flags, and question/answer/authority/additional counts. Flag layout is QR (1), Opcode (4), C (1), TC (1), T (1), Z (4), RCODE (4). C and T have LLMNR-specific meanings, so the public fields use Conflict and Tentative rather than DNS AA and RD.

`DecodeHeader([]byte) (Header, error)` is a small transport-independent component for the eventual gopacket decoder. Using only the standard library lets us explain and verify the wire format before adding packet-layer integration. No gopacket dependency or full-message parsing is present yet.

Check length before any indexing; return an error for fewer than 12 bytes. Accept trailing bytes because questions and records follow the header. Preserve all flag values, including the reserved nibble, so analysis can report unusual input. Decode counts without assuming that the stated records actually exist. Protocol behavior validation and section bounds checking belong to later work.

Tests use literal query and response payloads from the TShark baseline, independent single-field flag fixtures, distinct count values to reveal offset/byte-order errors, and all short lengths 0 through 11. Synthetic fixtures exercise decoding and are not assertions of protocol-valid messages. Tests were added alongside implementation, not run in a red-green TDD sequence. `go test ./...` and `go vet ./...` passed on Go 1.27.0 windows/amd64. The module declares Go 1.22; that version was not separately tested.
