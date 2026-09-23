package gologix

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// SendRRDataAddresses contains optional originator-to-target and
// target-to-originator IPv4 Sockaddr Info CPF items.
type SendRRDataAddresses struct {
	OT *net.UDPAddr
	TO *net.UDPAddr
}

// EncodeSendRRData encodes one complete EtherNet/IP SendRRData packet.
func EncodeSendRRData(session uint32, timeout uint16, context uint64, cip []byte, addresses SendRRDataAddresses) ([]byte, error) {
	const cpfOverhead = 16
	socketCount := 0
	if addresses.OT != nil {
		socketCount++
	}
	if addresses.TO != nil {
		socketCount++
	}
	payloadLength := cpfOverhead + len(cip) + socketCount*20
	if payloadLength > 65535 {
		return nil, errors.New("SendRRData CIP payload is too large")
	}
	packet := make([]byte, EncapsulationHeaderSize+payloadLength)
	binary.LittleEndian.PutUint16(packet[0:2], uint16(cipCommandSendRRData))
	binary.LittleEndian.PutUint16(packet[2:4], uint16(payloadLength))
	binary.LittleEndian.PutUint32(packet[4:8], session)
	binary.LittleEndian.PutUint64(packet[12:20], context)
	binary.LittleEndian.PutUint16(packet[28:30], timeout)
	binary.LittleEndian.PutUint16(packet[30:32], uint16(2+socketCount))
	binary.LittleEndian.PutUint16(packet[32:34], uint16(cipItem_Null))
	binary.LittleEndian.PutUint16(packet[36:38], uint16(cipItem_UnconnectedData))
	binary.LittleEndian.PutUint16(packet[38:40], uint16(len(cip)))
	copy(packet[40:], cip)
	offset := 40 + len(cip)
	for _, item := range []struct {
		typeID  CIPItemID
		address *net.UDPAddr
	}{{cipItem_SockAddrInfo_OT, addresses.OT}, {cipItem_SockAddrInfo_TO, addresses.TO}} {
		if item.address == nil {
			continue
		}
		encoded, err := encodeSockaddrInfo(item.address)
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint16(packet[offset:offset+2], uint16(item.typeID))
		binary.LittleEndian.PutUint16(packet[offset+2:offset+4], 16)
		copy(packet[offset+4:offset+20], encoded)
		offset += 20
	}
	return packet, nil
}

// DecodeSendRRData strictly decodes one complete SendRRData response packet.
func DecodeSendRRData(packet []byte, session uint32, context uint64) ([]byte, SendRRDataAddresses, error) {
	payload, err := decodeEncapsulation(packet, uint16(cipCommandSendRRData), session, context)
	if err != nil {
		return nil, SendRRDataAddresses{}, err
	}
	if len(payload) < 16 {
		return nil, SendRRDataAddresses{}, errors.New("SendRRData CPF is truncated")
	}
	if binary.LittleEndian.Uint32(payload[0:4]) != 0 {
		return nil, SendRRDataAddresses{}, errors.New("SendRRData interface handle must be zero")
	}
	if binary.LittleEndian.Uint16(payload[4:6]) != 0 {
		return nil, SendRRDataAddresses{}, errors.New("SendRRData response timeout must be zero")
	}
	itemCount := int(binary.LittleEndian.Uint16(payload[6:8]))
	if itemCount < 2 || itemCount > 4 {
		return nil, SendRRDataAddresses{}, errors.New("SendRRData CPF item count must be between two and four")
	}
	if binary.LittleEndian.Uint16(payload[8:10]) != uint16(cipItem_Null) || binary.LittleEndian.Uint16(payload[10:12]) != 0 {
		return nil, SendRRDataAddresses{}, errors.New("SendRRData first item must be an empty null address")
	}
	if binary.LittleEndian.Uint16(payload[12:14]) != uint16(cipItem_UnconnectedData) {
		return nil, SendRRDataAddresses{}, errors.New("SendRRData second item must be unconnected data")
	}
	length := int(binary.LittleEndian.Uint16(payload[14:16]))
	if len(payload) < 16+length {
		return nil, SendRRDataAddresses{}, fmt.Errorf("SendRRData unconnected data length %d exceeds payload length %d", length, len(payload)-16)
	}
	cip := append([]byte(nil), payload[16:16+length]...)
	offset := 16 + length
	addresses := SendRRDataAddresses{}
	for index := 2; index < itemCount; index++ {
		if len(payload)-offset < 4 {
			return nil, SendRRDataAddresses{}, errors.New("SendRRData socket item header is truncated")
		}
		typeID := CIPItemID(binary.LittleEndian.Uint16(payload[offset : offset+2]))
		itemLength := int(binary.LittleEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4
		if itemLength != 16 || len(payload)-offset < itemLength {
			return nil, SendRRDataAddresses{}, errors.New("SendRRData socket address length must be 16")
		}
		address, parseErr := decodeSockaddrInfo(payload[offset : offset+itemLength])
		if parseErr != nil {
			return nil, SendRRDataAddresses{}, parseErr
		}
		switch typeID {
		case cipItem_SockAddrInfo_OT:
			if addresses.OT != nil {
				return nil, SendRRDataAddresses{}, errors.New("SendRRData has duplicate O->T socket address type")
			}
			addresses.OT = address
		case cipItem_SockAddrInfo_TO:
			if addresses.TO != nil {
				return nil, SendRRDataAddresses{}, errors.New("SendRRData has duplicate T->O socket address type")
			}
			addresses.TO = address
		default:
			return nil, SendRRDataAddresses{}, fmt.Errorf("SendRRData socket item type 0x%04x is unsupported", typeID)
		}
		offset += itemLength
	}
	if offset != len(payload) {
		return nil, SendRRDataAddresses{}, errors.New("SendRRData CPF length does not match its item count")
	}
	return cip, addresses, nil
}

func decodeEncapsulation(packet []byte, command uint16, session uint32, context uint64) ([]byte, error) {
	_, payload, err := DecodeEncapsulation(packet, command, session, context)
	return payload, err
}

func encodeSockaddrInfo(address *net.UDPAddr) ([]byte, error) {
	if address == nil || address.Port < 1 || address.Port > 65535 {
		return nil, errors.New("socket address port must be between 1 and 65535")
	}
	ip := address.IP.To4()
	if ip == nil {
		return nil, errors.New("socket address family must be IPv4")
	}
	encoded := make([]byte, 16)
	binary.BigEndian.PutUint16(encoded[0:2], 2)
	binary.BigEndian.PutUint16(encoded[2:4], uint16(address.Port))
	copy(encoded[4:8], ip)
	return encoded, nil
}

func decodeSockaddrInfo(encoded []byte) (*net.UDPAddr, error) {
	if len(encoded) != 16 {
		return nil, errors.New("socket address length must be 16")
	}
	if binary.BigEndian.Uint16(encoded[0:2]) != 2 {
		return nil, errors.New("socket address family must be IPv4")
	}
	port := binary.BigEndian.Uint16(encoded[2:4])
	if port == 0 {
		return nil, errors.New("socket address port must be non-zero")
	}
	for _, value := range encoded[8:16] {
		if value != 0 {
			return nil, errors.New("socket address reserved bytes must be zero")
		}
	}
	return &net.UDPAddr{IP: append(net.IP(nil), encoded[4:8]...), Port: int(port)}, nil
}
