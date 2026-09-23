package gologix

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	EncapsulationHeaderSize             = 24
	EncapsulationCommandRegisterSession = uint16(cipCommandRegisterSession)
)

// EncapsulationHeader is the validated EtherNet/IP encapsulation header.
type EncapsulationHeader struct {
	Command uint16
	Length  uint16
	Session uint32
	Status  uint32
	Context uint64
	Options uint32
}

// DecodeEncapsulation validates a complete packet against the request
// correlation fields and returns an independently owned payload.
func DecodeEncapsulation(packet []byte, command uint16, session uint32, context uint64) (EncapsulationHeader, []byte, error) {
	return decodeEncapsulationPacket(packet, command, session, context, false)
}

// EncodeRegisterSession encodes a Register Session request for protocol
// version one with zero option flags.
func EncodeRegisterSession(context uint64) []byte {
	packet := make([]byte, EncapsulationHeaderSize+4)
	binary.LittleEndian.PutUint16(packet[0:2], EncapsulationCommandRegisterSession)
	binary.LittleEndian.PutUint16(packet[2:4], 4)
	binary.LittleEndian.PutUint64(packet[12:20], context)
	binary.LittleEndian.PutUint16(packet[24:26], 1)
	return packet
}

// DecodeRegisterSessionResponse validates a Register Session response and
// returns the nonzero session assigned by the target.
func DecodeRegisterSessionResponse(packet []byte, context uint64) (uint32, error) {
	header, payload, err := decodeEncapsulationPacket(packet, EncapsulationCommandRegisterSession, 0, context, true)
	if err != nil {
		return 0, err
	}
	if len(payload) != 4 {
		return 0, fmt.Errorf("Register Session payload length is %d, want 4", len(payload))
	}
	if binary.LittleEndian.Uint16(payload[0:2]) != 1 || binary.LittleEndian.Uint16(payload[2:4]) != 0 {
		return 0, errors.New("Register Session response has unsupported protocol version or options")
	}
	return header.Session, nil
}

func decodeEncapsulationPacket(packet []byte, command uint16, session uint32, context uint64, acceptAssignedSession bool) (EncapsulationHeader, []byte, error) {
	if len(packet) < EncapsulationHeaderSize {
		return EncapsulationHeader{}, nil, errors.New("encapsulation header is short")
	}
	header := EncapsulationHeader{
		Command: binary.LittleEndian.Uint16(packet[0:2]),
		Length:  binary.LittleEndian.Uint16(packet[2:4]),
		Session: binary.LittleEndian.Uint32(packet[4:8]),
		Status:  binary.LittleEndian.Uint32(packet[8:12]),
		Context: binary.LittleEndian.Uint64(packet[12:20]),
		Options: binary.LittleEndian.Uint32(packet[20:24]),
	}
	if int(header.Length) != len(packet)-EncapsulationHeaderSize {
		return header, nil, fmt.Errorf("encapsulation length %d does not match packet length %d", header.Length, len(packet))
	}
	if header.Command != command {
		return header, nil, fmt.Errorf("encapsulation command 0x%04x does not match 0x%04x", header.Command, command)
	}
	if (!acceptAssignedSession && header.Session != session) || (acceptAssignedSession && header.Session == 0) {
		return header, nil, fmt.Errorf("encapsulation session 0x%08x is invalid", header.Session)
	}
	if header.Status != 0 {
		return header, nil, fmt.Errorf("encapsulation status 0x%08x", header.Status)
	}
	if header.Context != context {
		return header, nil, fmt.Errorf("encapsulation context 0x%016x does not match request", header.Context)
	}
	if header.Options != 0 {
		return header, nil, fmt.Errorf("encapsulation options 0x%08x are unsupported", header.Options)
	}
	return header, append([]byte(nil), packet[EncapsulationHeaderSize:]...), nil
}
