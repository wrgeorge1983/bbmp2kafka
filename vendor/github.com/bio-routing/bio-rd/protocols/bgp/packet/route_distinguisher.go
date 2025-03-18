package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/bio-routing/tflow2/convert"
)

const (
	// RouteDistinguisherLength is the length of a route distinguisher in bytes
	RouteDistinguisherLength = 8

	// RouteDistinguisherTypeAdministratorSubfield2Octet is the RD type where Administrator subfield is 2 octets
	RouteDistinguisherTypeAdministratorSubfield2Octet = 0

	// RouteDistinguisherTypeAdministratorSubfield4Octet is the RD type where Administrator subfield is 4 octets
	RouteDistinguisherTypeAdministratorSubfield4Octet = 1

	// RouteDistinguisherTypeAdministratorSubfield4OctetIP is the RD type where Administrator subfield is a 4 octet IP address
	RouteDistinguisherTypeAdministratorSubfield4OctetIP = 2
)

// RouteDistinguisher represents a BGP route distinguisher
type RouteDistinguisher struct {
	Type          uint16
	Administrator []byte
	AssignedNumber []byte
}

// Copy returns a copy of the RouteDistinguisher
func (rd *RouteDistinguisher) Copy() *RouteDistinguisher {
	administratorCopy := make([]byte, len(rd.Administrator))
	copy(administratorCopy, rd.Administrator)

	assignedNumberCopy := make([]byte, len(rd.AssignedNumber))
	copy(assignedNumberCopy, rd.AssignedNumber)

	return &RouteDistinguisher{
		Type:          rd.Type,
		Administrator: administratorCopy,
		AssignedNumber: assignedNumberCopy,
	}
}

// Serialize serializes an RD to a byte buffer
func (rd *RouteDistinguisher) Serialize(buf *bytes.Buffer) uint8 {
	buf.Write(convert.Uint16Byte(rd.Type))
	buf.Write(rd.Administrator)
	buf.Write(rd.AssignedNumber)
	return RouteDistinguisherLength
}

// deserializeRouteDistinguisher deserializes an RD
func deserializeRouteDistinguisher(b []byte) (*RouteDistinguisher, error) {
	if len(b) < RouteDistinguisherLength {
		return nil, fmt.Errorf("not enough bytes to decode route distinguisher: got %d, expected %d", len(b), RouteDistinguisherLength)
	}

	rd := RouteDistinguisher{
		Type: binary.BigEndian.Uint16(b[0:2]),
	}

	switch rd.Type {
	case RouteDistinguisherTypeAdministratorSubfield2Octet:
		rd.Administrator = make([]byte, 2)
		copy(rd.Administrator, b[2:4])
		rd.AssignedNumber = make([]byte, 4)
		copy(rd.AssignedNumber, b[4:8])
	case RouteDistinguisherTypeAdministratorSubfield4Octet:
		rd.Administrator = make([]byte, 4)
		copy(rd.Administrator, b[2:6])
		rd.AssignedNumber = make([]byte, 2)
		copy(rd.AssignedNumber, b[6:8])
	case RouteDistinguisherTypeAdministratorSubfield4OctetIP:
		rd.Administrator = make([]byte, 4)
		copy(rd.Administrator, b[2:6])
		rd.AssignedNumber = make([]byte, 2)
		copy(rd.AssignedNumber, b[6:8])
	default:
		return nil, fmt.Errorf("unknown RD type: %d", rd.Type)
	}
	
	return &rd, nil
}

// String returns the string representation of the RD
func (rd *RouteDistinguisher) String() string {
	switch rd.Type {
	case RouteDistinguisherTypeAdministratorSubfield2Octet:
		return fmt.Sprintf("%d:%d", binary.BigEndian.Uint16(rd.Administrator), binary.BigEndian.Uint32(rd.AssignedNumber))
	case RouteDistinguisherTypeAdministratorSubfield4Octet:
		return fmt.Sprintf("%d:%d", binary.BigEndian.Uint32(rd.Administrator), binary.BigEndian.Uint16(rd.AssignedNumber))
	case RouteDistinguisherTypeAdministratorSubfield4OctetIP:
		return fmt.Sprintf("%s:%d", net.IP(rd.Administrator).String(), binary.BigEndian.Uint16(rd.AssignedNumber))
	default:
		return fmt.Sprintf("Unknown RD type: %d", rd.Type)
	}
}

// ParseRouteDistinguisher parses RD from string representation
func ParseRouteDistinguisher(s string) (*RouteDistinguisher, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid RD format: %s (expected format: x:y)", s)
	}

	// Try to parse admin part as an IP address
	ip := net.ParseIP(parts[0])
	if ip != nil {
		// It's type 2 (IP:value)
		ip = ip.To4()
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv4 address in RD: %s", parts[0])
		}

		assignedNumber, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid assigned number in RD: %s", parts[1])
		}

		return &RouteDistinguisher{
			Type:          RouteDistinguisherTypeAdministratorSubfield4OctetIP,
			Administrator: []byte(ip),
			AssignedNumber: convert.Uint16Byte(uint16(assignedNumber)),
		}, nil
	}

	// Try to parse admin part as a number and determine if it's type 0 or 1
	admin, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid administrator value in RD: %s", parts[0])
	}

	assignedNumber, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid assigned number in RD: %s", parts[1])
	}

	// Determine RD type based on admin value range
	if admin <= 0xFFFF {
		// Type 0
		return &RouteDistinguisher{
			Type:          RouteDistinguisherTypeAdministratorSubfield2Octet,
			Administrator: convert.Uint16Byte(uint16(admin)),
			AssignedNumber: convert.Uint32Byte(uint32(assignedNumber)),
		}, nil
	}

	// Type 1
	if assignedNumber > 0xFFFF {
		return nil, fmt.Errorf("assigned number too large for RD type 1: %d", assignedNumber)
	}

	return &RouteDistinguisher{
		Type:          RouteDistinguisherTypeAdministratorSubfield4Octet,
		Administrator: convert.Uint32Byte(uint32(admin)),
		AssignedNumber: convert.Uint16Byte(uint16(assignedNumber)),
	}, nil
}