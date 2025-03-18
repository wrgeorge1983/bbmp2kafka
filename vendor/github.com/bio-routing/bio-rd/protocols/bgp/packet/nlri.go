package packet

import (
	"bytes"
	"fmt"
	"math"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bio-rd/util/decode"
	"github.com/bio-routing/tflow2/convert"
)

const (
	PathIdentifierLen = 4
	BytesPerLabel     = 3
	BitsPerLabel      = BytesPerLabel * 8
)

// NLRI represents a Network Layer Reachability Information
type NLRI struct {
	PathIdentifier     uint32
	LabelStack         []LabelStackEntry
	RouteDistinguisher *RouteDistinguisher
	Prefix             *bnet.Prefix
	Next               *NLRI
}

func decodeNLRIs(buf *bytes.Buffer, length uint16, afi uint16, safi uint8, addPath bool) (*NLRI, error) {
	var ret *NLRI
	var eol *NLRI
	var nlri *NLRI
	var err error
	var consumed uint8
	p := uint16(0)

	for p < length {
		nlri, consumed, err = decodeNLRI(buf, afi, safi, addPath)
		if err != nil {
			return nil, fmt.Errorf("unable to decode NLRI: %w", err)
		}
		p += uint16(consumed)

		if ret == nil {
			ret = nlri
			eol = nlri
			continue
		}

		eol.Next = nlri
		eol = nlri
	}

	return ret, nil
}

func decodeNLRI(buf *bytes.Buffer, afi uint16, safi uint8, addPath bool) (*NLRI, uint8, error) {
	nlri := &NLRI{}

	consumed := uint8(0)

	if addPath {
		err := decode.Decode(buf, []interface{}{
			&nlri.PathIdentifier,
		})
		if err != nil {
			return nil, consumed, fmt.Errorf("unable to decode path identifier: %w", err)
		}

		consumed += PathIdentifierLen
	}

	pfxLen, err := buf.ReadByte()
	if err != nil {
		return nil, consumed, err
	}
	consumed++

	// Handle label(s) for labeled unicast or VPN routes
	if safi == SAFILabeledUnicast || safi == SAFIVPNUnicast {
		nlri.LabelStack = make([]LabelStackEntry, 0, 1)
		for {
			lse, err := decodeLabelStackEntry(buf)
			if err != nil {
				return nil, consumed, fmt.Errorf("decode label stack entry failed: %w", err)
			}

			consumed += BytesPerLabel
			pfxLen -= BitsPerLabel
			nlri.LabelStack = append(nlri.LabelStack, lse)

			if lse.isBottomOfStack() {
				break
			}
		}
	}

	// Handle Route Distinguisher for VPN routes
	if safi == SAFIVPNUnicast {
		if buf.Len() < RouteDistinguisherLength {
			return nil, consumed, fmt.Errorf("not enough bytes to decode route distinguisher")
		}

		rdBytes := make([]byte, RouteDistinguisherLength)
		n, err := buf.Read(rdBytes)
		if err != nil {
			return nil, consumed, fmt.Errorf("unable to read route distinguisher: %w", err)
		}
		
		if n != RouteDistinguisherLength {
			return nil, consumed, fmt.Errorf("expected %d RD bytes, read only %d", RouteDistinguisherLength, n)
		}
		
		rd, err := deserializeRouteDistinguisher(rdBytes)
		if err != nil {
			return nil, consumed, fmt.Errorf("unable to decode route distinguisher: %w", err)
		}
		
		nlri.RouteDistinguisher = rd
		consumed += RouteDistinguisherLength
		pfxLen -= RouteDistinguisherLength * 8 // Subtract RD bits from prefix length
	}

	numBytes := uint8(BytesInAddr(pfxLen))
	bytes := make([]byte, numBytes)

	r, err := buf.Read(bytes)
	consumed += uint8(r)
	if err != nil {
		return nil, consumed, err
	}
	if r < int(numBytes) {
		return nil, consumed, fmt.Errorf("expected %d bytes for NLRI, only %d remaining", numBytes, r)
	}

	pfx, err := deserializePrefix(bytes, pfxLen, afi)
	if err != nil {
		return nil, consumed, err
	}
	nlri.Prefix = pfx

	return nlri, consumed, nil
}

func (n *NLRI) serialize(buf *bytes.Buffer, addPath bool, safi uint8) uint8 {
	numBytes := uint8(0)

	if addPath {
		buf.Write(convert.Uint32Byte(n.PathIdentifier))
		numBytes += 4
	}

	pfxLen := n.Prefix.Len()
	// Account for label stack in prefix length
	if safi == SAFILabeledUnicast || safi == SAFIVPNUnicast {
		pfxLen += uint8(len(n.LabelStack) * BitsPerLabel)
	}
	
	// Account for Route Distinguisher in prefix length
	if safi == SAFIVPNUnicast && n.RouteDistinguisher != nil {
		pfxLen += RouteDistinguisherLength * 8
	}

	buf.WriteByte(pfxLen)
	numBytes++

	// Write label stack for labeled unicast or VPN routes
	if safi == SAFILabeledUnicast || safi == SAFIVPNUnicast {
		labelCount := len(n.LabelStack)
		for i, l := range n.LabelStack {
			l.serialize(buf, i == labelCount-1)
			numBytes += BytesPerLabel
		}
	}

	// Write Route Distinguisher for VPN routes
	if safi == SAFIVPNUnicast && n.RouteDistinguisher != nil {
		numBytes += n.RouteDistinguisher.Serialize(buf)
	}

	pfxNumBytes := BytesInAddr(n.Prefix.Len())
	buf.Write(n.Prefix.Addr().Bytes()[:pfxNumBytes])
	numBytes += pfxNumBytes

	return numBytes
}

// BytesInAddr gets the amount of bytes needed to encode an NLRI of prefix length pfxlen
func BytesInAddr(pfxlen uint8) uint8 {
	return uint8(math.Ceil(float64(pfxlen) / 8))
}
