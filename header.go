// Package llmnr decodes Link-Local Multicast Name Resolution messages.
package llmnr

import (
	"encoding/binary"
	"fmt"
)

// HeaderSize is the fixed LLMNR header length in bytes.
const HeaderSize = 12

// Header contains the fields defined by RFC 4795 section 2.1.1.
// Counts describe the sections that follow; decoding a header does not
// establish that those sections are present or valid.
type Header struct {
	ID        uint16
	QR        bool // True for a response, false for a query.
	Opcode    uint8
	Conflict  bool
	Truncated bool
	Tentative bool
	Reserved  uint8 // Four Z bits, retained for inspection.
	RCode     uint8
	QDCount   uint16
	ANCount   uint16
	NSCount   uint16
	ARCount   uint16
}

// DecodeHeader reads the first HeaderSize bytes of an LLMNR message.
// It accepts trailing section bytes and reports short input without panicking.
// It decodes wire values without enforcing responder behavior or count limits.
func DecodeHeader(data []byte) (Header, error) {
	if len(data) < HeaderSize {
		return Header{}, fmt.Errorf("llmnr: short header: got %d bytes, need %d", len(data), HeaderSize)
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	return Header{
		ID:        binary.BigEndian.Uint16(data[0:2]),
		QR:        flags&0x8000 != 0,
		Opcode:    uint8((flags >> 11) & 0x0f),
		Conflict:  flags&0x0400 != 0,
		Truncated: flags&0x0200 != 0,
		Tentative: flags&0x0100 != 0,
		Reserved:  uint8((flags >> 4) & 0x0f),
		RCode:     uint8(flags & 0x0f),
		QDCount:   binary.BigEndian.Uint16(data[4:6]),
		ANCount:   binary.BigEndian.Uint16(data[6:8]),
		NSCount:   binary.BigEndian.Uint16(data[8:10]),
		ARCount:   binary.BigEndian.Uint16(data[10:12]),
	}, nil
}
