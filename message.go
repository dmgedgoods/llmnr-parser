package llmnr

import "fmt"

// Message contains the currently supported LLMNR sections.
type Message struct {
	Header      Header
	Questions   []Question
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additionals []ResourceRecord
}

// DecodeMessage decodes one complete LLMNR payload, starting at its ID field.
// It checks structural completeness, not resolver policy. Compressed names
// are currently unsupported. Trailing bytes are
// rejected. On failure it returns nil, never a partially decoded message.
func DecodeMessage(data []byte) (*Message, error) {
	header, err := DecodeHeader(data)
	if err != nil {
		return nil, err
	}
	message := &Message{Header: header}
	offset := HeaderSize
	// Append only after successfully reading an entry, rather than allocating
	// slices directly from untrusted header counts.
	for i := 0; i < int(header.QDCount); i++ {
		question, next, err := DecodeQuestion(data, offset)
		if err != nil {
			return nil, fmt.Errorf("llmnr: question %d at offset %d: %w", i+1, offset, err)
		}
		message.Questions = append(message.Questions, question)
		offset = next
	}
	for _, section := range []struct {
		name    string
		count   uint16
		records *[]ResourceRecord
	}{
		{"answer", header.ANCount, &message.Answers},
		{"authority", header.NSCount, &message.Authorities},
		{"additional", header.ARCount, &message.Additionals},
	} {
		for i := 0; i < int(section.count); i++ {
			record, next, err := DecodeResourceRecord(data, offset)
			if err != nil {
				return nil, fmt.Errorf("llmnr: %s %d at offset %d: %w", section.name, i+1, offset, err)
			}
			*section.records = append(*section.records, record)
			offset = next
		}
	}
	if offset != len(data) {
		return nil, fmt.Errorf("llmnr: %d trailing bytes after declared sections", len(data)-offset)
	}
	return message, nil
}
