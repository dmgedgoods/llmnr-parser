package llmnr

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Question describes a requested name, record type, and class.
type Question struct {
	// Name preserves case and uses dots between labels, without a trailing dot.
	// The root is ".". Literal dots, backslashes, and non-printable label bytes
	// are escaped as decimal \DDD so label boundaries remain unambiguous.
	Name  string
	Type  uint16
	Class uint16
}

// DecodeQuestion reads one question at offset in the complete LLMNR message.
// On success, next is the offset immediately after QCLASS. On error, next
// is the original offset. This incremental decoder supports uncompressed names.
func DecodeQuestion(data []byte, offset int) (question Question, next int, err error) {
	name, end, err := decodeName(data, offset)
	if err != nil {
		return Question{}, offset, err
	}
	if len(data)-end < 4 {
		return Question{}, offset, fmt.Errorf("llmnr: short question type/class at offset %d", end)
	}
	return Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[end : end+2]),
		Class: binary.BigEndian.Uint16(data[end+2 : end+4]),
	}, end + 4, nil
}

func decodeName(data []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(data) {
		return "", offset, fmt.Errorf("llmnr: name offset %d outside message", offset)
	}
	start := offset
	var name strings.Builder
	for {
		if offset >= len(data) {
			return "", start, fmt.Errorf("llmnr: unterminated name at offset %d", start)
		}
		length := int(data[offset])
		switch length & 0xc0 {
		case 0xc0:
			return "", start, fmt.Errorf("llmnr: name compression not supported yet at offset %d", offset)
		case 0x40, 0x80:
			return "", start, fmt.Errorf("llmnr: unsupported label encoding at offset %d", offset)
		}
		offset++
		if offset-start+length > 255 {
			return "", start, fmt.Errorf("llmnr: name exceeds 255 bytes at offset %d", start)
		}
		if length == 0 {
			if name.Len() == 0 {
				return ".", offset, nil
			}
			return name.String(), offset, nil
		}
		if length > len(data)-offset {
			return "", start, fmt.Errorf("llmnr: short label at offset %d", offset-1)
		}
		if name.Len() > 0 {
			name.WriteByte('.')
		}
		for _, b := range data[offset : offset+length] {
			if b <= ' ' || b >= 127 || b == '.' || b == '\\' {
				fmt.Fprintf(&name, "\\%03d", b)
			} else {
				name.WriteByte(b)
			}
		}
		offset += length
	}
}
