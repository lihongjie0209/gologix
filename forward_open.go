package gologix

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type Class1Priority uint8

const (
	Class1PriorityLow Class1Priority = iota
	Class1PriorityHigh
	Class1PriorityScheduled
	Class1PriorityUrgent
)

type Class1ConnectionType uint8

const (
	Class1ConnectionMulticast    Class1ConnectionType = 1
	Class1ConnectionPointToPoint Class1ConnectionType = 2
)

type ConnectionIdentity struct {
	ConnectionSerial uint16
	VendorID         uint16
	OriginatorSerial uint32
}

type ForwardOpenRequest struct {
	OTConnectionID        uint32
	TOConnectionID        uint32
	Identity              ConnectionIdentity
	TimeoutMultiplier     uint8
	RPIMicroseconds       uint32
	Priority              Class1Priority
	InputConnectionType   Class1ConnectionType
	VariableLength        bool
	ConfigurationAssembly *uint16
	OutputAssembly        uint16
	InputAssembly         uint16
	OutputApplicationSize int
	InputApplicationSize  int
	RunIdleHeader         bool
}

type ForwardOpenResponse struct {
	OTConnectionID    uint32
	TOConnectionID    uint32
	OTRPIMicroseconds uint32
	TORPIMicroseconds uint32
	SocketAddresses   SendRRDataAddresses
}

func EncodeForwardOpen(request ForwardOpenRequest, route []byte) ([]byte, error) {
	if request.RPIMicroseconds == 0 {
		return nil, errors.New("Forward Open RPI must be positive")
	}
	if request.TimeoutMultiplier > 7 {
		return nil, errors.New("Forward Open timeout multiplier must be 0..7")
	}
	if request.Priority > Class1PriorityUrgent {
		return nil, errors.New("unsupported Forward Open priority")
	}
	if request.InputConnectionType != Class1ConnectionMulticast && request.InputConnectionType != Class1ConnectionPointToPoint {
		return nil, errors.New("unsupported Forward Open input connection type")
	}
	if request.OutputApplicationSize < 0 || request.OutputApplicationSize > MaxClass1ApplicationSize || request.InputApplicationSize < 0 || request.InputApplicationSize > MaxClass1ApplicationSize {
		return nil, errors.New("Forward Open application size exceeds Class 1 bounds")
	}
	path, err := class1ConnectionPath(route, request.ConfigurationAssembly, request.OutputAssembly, request.InputAssembly)
	if err != nil {
		return nil, err
	}
	otSize := request.OutputApplicationSize + 2
	if request.RunIdleHeader {
		otSize += 4
	}
	toSize := request.InputApplicationSize + 2
	otParameters, err := standardConnectionParameters(Class1ConnectionPointToPoint, request.Priority, request.VariableLength, otSize)
	if err != nil {
		return nil, fmt.Errorf("O->T parameters: %w", err)
	}
	toParameters, err := standardConnectionParameters(request.InputConnectionType, request.Priority, request.VariableLength, toSize)
	if err != nil {
		return nil, fmt.Errorf("T->O parameters: %w", err)
	}
	packet := make([]byte, 42+len(path))
	packet[0], packet[1] = byte(CIPService_ForwardOpen), 2
	packet[2], packet[3], packet[4], packet[5] = 0x20, 0x06, 0x24, 0x01
	packet[6], packet[7] = 0x0a, 0x0e
	binary.LittleEndian.PutUint32(packet[8:12], request.OTConnectionID)
	binary.LittleEndian.PutUint32(packet[12:16], request.TOConnectionID)
	binary.LittleEndian.PutUint16(packet[16:18], request.Identity.ConnectionSerial)
	binary.LittleEndian.PutUint16(packet[18:20], request.Identity.VendorID)
	binary.LittleEndian.PutUint32(packet[20:24], request.Identity.OriginatorSerial)
	packet[24] = request.TimeoutMultiplier
	binary.LittleEndian.PutUint32(packet[28:32], request.RPIMicroseconds)
	binary.LittleEndian.PutUint16(packet[32:34], otParameters)
	binary.LittleEndian.PutUint32(packet[34:38], request.RPIMicroseconds)
	binary.LittleEndian.PutUint16(packet[38:40], toParameters)
	packet[40], packet[41] = 0x01, byte(len(path)/2)
	copy(packet[42:], path)
	return packet, nil
}

func DecodeForwardOpenResponse(packet []byte, identity ConnectionIdentity) (ForwardOpenResponse, error) {
	data, err := decodeCIPResponse(packet, byte(CIPService_ForwardOpen))
	if err != nil {
		return ForwardOpenResponse{}, err
	}
	if len(data) < 26 {
		return ForwardOpenResponse{}, errors.New("Forward Open response is truncated")
	}
	if binary.LittleEndian.Uint16(data[8:10]) != identity.ConnectionSerial || binary.LittleEndian.Uint16(data[10:12]) != identity.VendorID || binary.LittleEndian.Uint32(data[12:16]) != identity.OriginatorSerial {
		return ForwardOpenResponse{}, errors.New("Forward Open response identity does not match request")
	}
	otAPI, toAPI := binary.LittleEndian.Uint32(data[16:20]), binary.LittleEndian.Uint32(data[20:24])
	if otAPI == 0 {
		return ForwardOpenResponse{}, errors.New("Forward Open O->T API must be positive")
	}
	if toAPI == 0 {
		return ForwardOpenResponse{}, errors.New("Forward Open T->O API must be positive")
	}
	replyWords := int(data[24])
	if data[25] != 0 || len(data) != 26+replyWords*2 {
		return ForwardOpenResponse{}, errors.New("Forward Open application reply length or reserved byte is invalid")
	}
	return ForwardOpenResponse{
		OTConnectionID:    binary.LittleEndian.Uint32(data[0:4]),
		TOConnectionID:    binary.LittleEndian.Uint32(data[4:8]),
		OTRPIMicroseconds: otAPI,
		TORPIMicroseconds: toAPI,
	}, nil
}

func EncodeForwardClose(identity ConnectionIdentity, route []byte, configuration *uint16, output, input uint16) ([]byte, error) {
	path, err := class1ConnectionPath(route, configuration, output, input)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 18+len(path))
	packet[0], packet[1] = byte(CIPService_ForwardClose), 2
	packet[2], packet[3], packet[4], packet[5] = 0x20, 0x06, 0x24, 0x01
	packet[6], packet[7] = 0x0a, 0x0e
	binary.LittleEndian.PutUint16(packet[8:10], identity.ConnectionSerial)
	binary.LittleEndian.PutUint16(packet[10:12], identity.VendorID)
	binary.LittleEndian.PutUint32(packet[12:16], identity.OriginatorSerial)
	packet[16] = byte(len(path) / 2)
	copy(packet[18:], path)
	return packet, nil
}

func DecodeForwardCloseResponse(packet []byte, identity ConnectionIdentity) error {
	data, err := decodeCIPResponse(packet, byte(CIPService_ForwardClose))
	if err != nil {
		return err
	}
	if len(data) < 10 {
		return errors.New("Forward Close response is truncated")
	}
	if binary.LittleEndian.Uint16(data[0:2]) != identity.ConnectionSerial || binary.LittleEndian.Uint16(data[2:4]) != identity.VendorID || binary.LittleEndian.Uint32(data[4:8]) != identity.OriginatorSerial {
		return errors.New("Forward Close response identity does not match request")
	}
	replyWords := int(data[8])
	if data[9] != 0 || len(data) != 10+replyWords*2 {
		return errors.New("Forward Close application reply length or reserved byte is invalid")
	}
	return nil
}

func standardConnectionParameters(connectionType Class1ConnectionType, priority Class1Priority, variable bool, size int) (uint16, error) {
	if connectionType > Class1ConnectionPointToPoint || priority > Class1PriorityUrgent || size < 0 || size > 511 {
		return 0, errors.New("values do not fit a standard Forward Open")
	}
	parameters := uint16(connectionType)<<13 | uint16(priority)<<10 | uint16(size)
	if variable {
		parameters |= 1 << 9
	}
	return parameters, nil
}

func class1ConnectionPath(route []byte, configuration *uint16, output, input uint16) ([]byte, error) {
	if len(route)%2 != 0 {
		return nil, errors.New("route must contain a whole number of words")
	}
	path := append([]byte(nil), route...)
	path = append(path, 0x20, 0x04)
	if configuration != nil {
		path = appendLogicalSegment(path, 0x24, 0x25, *configuration)
	}
	path = appendLogicalSegment(path, 0x2c, 0x2d, output)
	path = appendLogicalSegment(path, 0x2c, 0x2d, input)
	if len(path)%2 != 0 || len(path)/2 > 255 {
		return nil, errors.New("connection path does not fit Forward Open path size")
	}
	return path, nil
}

func appendLogicalSegment(path []byte, shortType, longType byte, value uint16) []byte {
	if value <= 255 {
		return append(path, shortType, byte(value))
	}
	return append(path, longType, 0, byte(value), byte(value>>8))
}

func decodeCIPResponse(packet []byte, requestService byte) ([]byte, error) {
	if len(packet) < 4 {
		return nil, errors.New("CIP response is truncated")
	}
	if packet[0] != requestService|0x80 {
		return nil, fmt.Errorf("CIP response service 0x%02x does not match request 0x%02x", packet[0], requestService)
	}
	if packet[1] != 0 {
		return nil, errors.New("CIP response reserved byte is non-zero")
	}
	additionalBytes := int(packet[3]) * 2
	if len(packet) < 4+additionalBytes {
		return nil, errors.New("CIP response additional status is truncated")
	}
	if packet[2] != 0 {
		return nil, fmt.Errorf("CIP response status 0x%02x additional=%x", packet[2], packet[4:4+additionalBytes])
	}
	return packet[4+additionalBytes:], nil
}
