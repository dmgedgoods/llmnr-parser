package llmnr

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// ResourceRecord is the common format used in answer, authority, and additional
// sections. Name uses the same presentation as Question.Name.
type ResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16 // Raw field; OPT uses this for its UDP payload size.
	TTL      uint32 // Raw field; normally seconds, but OPT uses it for metadata.
	RDLength uint16
	RData    []byte     // Owned copy of the encoded record data.
	Address  netip.Addr // Valid only for decoded IN-class A and AAAA records.
}

// DecodeResourceRecord reads one record from the complete LLMNR message.
// It returns the offset after RDATA on success, or the original offset on error.
// Unknown types/classes retain their raw data with an invalid Address.
// Names currently support only the uncompressed form.
func DecodeResourceRecord(data []byte, offset int) (ResourceRecord, int, error) {
	name, end, err := decodeName(data, offset)
	if err != nil {
		return ResourceRecord{}, offset, err
	}
	// TYPE(2), CLASS(2), TTL(4), and RDLENGTH(2) follow the name.
	if len(data)-end < 10 {
		return ResourceRecord{}, offset, fmt.Errorf("llmnr: short resource record fields at offset %d", end)
	}
	record := ResourceRecord{
		Name:     name,
		Type:     binary.BigEndian.Uint16(data[end : end+2]),
		Class:    binary.BigEndian.Uint16(data[end+2 : end+4]),
		TTL:      binary.BigEndian.Uint32(data[end+4 : end+8]),
		RDLength: binary.BigEndian.Uint16(data[end+8 : end+10]),
	}
	end += 10
	length := int(record.RDLength)
	if length > len(data)-end {
		return ResourceRecord{}, offset, fmt.Errorf("llmnr: short record data at offset %d: got %d bytes, need %d", end, len(data)-end, length)
	}
	rdata := data[end : end+length]
	if record.Class == 1 { // IN: Internet address records.
		switch record.Type {
		case 1: // A
			if length != 4 {
				return ResourceRecord{}, offset, fmt.Errorf("llmnr: A record data length is %d, need 4", length)
			}
			record.Address = netip.AddrFrom4([4]byte(rdata))
		case 28: // AAAA
			if length != 16 {
				return ResourceRecord{}, offset, fmt.Errorf("llmnr: AAAA record data length is %d, need 16", length)
			}
			record.Address = netip.AddrFrom16([16]byte(rdata))
		}
	}
	record.RData = append([]byte(nil), rdata...)
	return record, end + length, nil
}
