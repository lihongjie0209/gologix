package gologix

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const MaxClass1ApplicationSize = 504

// Class1Packet is a decoded EtherNet/IP Class 1 UDP CPF packet. Data is an
// owned copy and can be modified independently of the encoded packet.
type Class1Packet struct {
	Sequence          uint32
	TransportSequence uint16
	Run               bool
	Data              []byte
}

// EncodeClass1CPF encodes Sequenced Address and Connected Data CPF items.
func EncodeClass1CPF(connectionID, sequence uint32, data []byte, runIdleHeader, run bool) ([]byte, error) {
	if connectionID == 0 {
		return nil, errors.New("Class 1 connection ID must be non-zero")
	}
	if len(data) > MaxClass1ApplicationSize {
		return nil, fmt.Errorf("Class 1 application data length %d exceeds %d", len(data), MaxClass1ApplicationSize)
	}
	runIdleBytes := 0
	if runIdleHeader {
		runIdleBytes = 4
	}
	packet := make([]byte, 20+runIdleBytes+len(data))
	binary.LittleEndian.PutUint16(packet[0:2], 2)
	binary.LittleEndian.PutUint16(packet[2:4], uint16(cipItem_SequenceAddress))
	binary.LittleEndian.PutUint16(packet[4:6], 8)
	binary.LittleEndian.PutUint32(packet[6:10], connectionID)
	binary.LittleEndian.PutUint32(packet[10:14], sequence)
	binary.LittleEndian.PutUint16(packet[14:16], uint16(cipItem_ConnectedData))
	binary.LittleEndian.PutUint16(packet[16:18], uint16(2+runIdleBytes+len(data)))
	binary.LittleEndian.PutUint16(packet[18:20], uint16(sequence))
	if runIdleHeader && run {
		binary.LittleEndian.PutUint32(packet[20:24], 1)
	}
	copy(packet[20+runIdleBytes:], data)
	return packet, nil
}

// DecodeClass1CPF strictly decodes one complete Class 1 UDP CPF packet.
func DecodeClass1CPF(packet []byte, connectionID uint32, applicationSize int, runIdleHeader bool) (Class1Packet, error) {
	if connectionID == 0 {
		return Class1Packet{}, errors.New("expected Class 1 connection ID must be non-zero")
	}
	if applicationSize < 0 || applicationSize > MaxClass1ApplicationSize {
		return Class1Packet{}, fmt.Errorf("Class 1 application size %d is invalid", applicationSize)
	}
	runIdleBytes := 0
	if runIdleHeader {
		runIdleBytes = 4
	}
	expectedLength := 20 + runIdleBytes + applicationSize
	if len(packet) != expectedLength {
		return Class1Packet{}, fmt.Errorf("Class 1 CPF length %d does not match expected length %d", len(packet), expectedLength)
	}
	if binary.LittleEndian.Uint16(packet[0:2]) != 2 {
		return Class1Packet{}, errors.New("Class 1 CPF item count must be two")
	}
	if binary.LittleEndian.Uint16(packet[2:4]) != uint16(cipItem_SequenceAddress) {
		return Class1Packet{}, errors.New("Class 1 CPF first item must be a sequenced address")
	}
	if binary.LittleEndian.Uint16(packet[4:6]) != 8 {
		return Class1Packet{}, errors.New("Class 1 CPF sequenced address length must be eight")
	}
	if actual := binary.LittleEndian.Uint32(packet[6:10]); actual != connectionID {
		return Class1Packet{}, fmt.Errorf("Class 1 CPF connection ID 0x%08x does not match 0x%08x", actual, connectionID)
	}
	if binary.LittleEndian.Uint16(packet[14:16]) != uint16(cipItem_ConnectedData) {
		return Class1Packet{}, errors.New("Class 1 CPF second item must be connected data")
	}
	if actual := int(binary.LittleEndian.Uint16(packet[16:18])); actual != 2+runIdleBytes+applicationSize {
		return Class1Packet{}, fmt.Errorf("Class 1 CPF connected data length %d does not match expected length %d", actual, 2+runIdleBytes+applicationSize)
	}
	sequence := binary.LittleEndian.Uint32(packet[10:14])
	transportSequence := binary.LittleEndian.Uint16(packet[18:20])
	if transportSequence != uint16(sequence) {
		return Class1Packet{}, fmt.Errorf("Class 1 CPF transport sequence 0x%04x does not match address sequence 0x%08x", transportSequence, sequence)
	}
	offset, run := 20, false
	if runIdleHeader {
		state := binary.LittleEndian.Uint32(packet[offset : offset+4])
		if state&^uint32(1) != 0 {
			return Class1Packet{}, fmt.Errorf("Class 1 CPF Run/Idle header 0x%08x has reserved bits", state)
		}
		run = state == 1
		offset += 4
	}
	return Class1Packet{
		Sequence:          sequence,
		TransportSequence: transportSequence,
		Run:               run,
		Data:              append([]byte(nil), packet[offset:]...),
	}, nil
}
