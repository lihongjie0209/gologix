package gologix

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestForwardOpenGolden(t *testing.T) {
	configuration := uint16(3)
	request := ForwardOpenRequest{
		OTConnectionID: 0x11223344, TOConnectionID: 0x55667788,
		Identity:          ConnectionIdentity{ConnectionSerial: 0x1234, VendorID: 0x5678, OriginatorSerial: 0x9abcdef0},
		TimeoutMultiplier: 4, RPIMicroseconds: 20000, Priority: Class1PriorityScheduled,
		InputConnectionType:   Class1ConnectionPointToPoint,
		ConfigurationAssembly: &configuration, OutputAssembly: 100, InputAssembly: 101,
		OutputApplicationSize: 8, InputApplicationSize: 16, RunIdleHeader: true,
	}
	packet, err := EncodeForwardOpen(request, []byte{1, 0})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("5402200624010a0e443322118877665534127856f0debc9a04000000204e00000e48204e0000124801050100200424032c642c65")
	if !bytes.Equal(packet, want) {
		t.Fatalf("packet = %x, want %x", packet, want)
	}
}

func TestForwardOpenExtendedPathAndValidation(t *testing.T) {
	configuration := uint16(300)
	request := ForwardOpenRequest{
		RPIMicroseconds: 2000, Priority: Class1PriorityUrgent,
		InputConnectionType: Class1ConnectionMulticast, VariableLength: true,
		ConfigurationAssembly: &configuration, OutputAssembly: 301, InputAssembly: 302,
		OutputApplicationSize: 1, InputApplicationSize: 2,
	}
	packet, err := EncodeForwardOpen(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantPath, _ := hex.DecodeString("200425002c012d002d012d002e01")
	if !bytes.Equal(packet[len(packet)-len(wantPath):], wantPath) {
		t.Fatalf("path=%x, want %x", packet[len(packet)-len(wantPath):], wantPath)
	}
	tests := []struct {
		name   string
		mutate func(*ForwardOpenRequest, *[]byte)
	}{
		{"route", func(_ *ForwardOpenRequest, route *[]byte) { *route = []byte{1} }},
		{"rpi", func(request *ForwardOpenRequest, _ *[]byte) { request.RPIMicroseconds = 0 }},
		{"priority", func(request *ForwardOpenRequest, _ *[]byte) { request.Priority = 4 }},
		{"transport", func(request *ForwardOpenRequest, _ *[]byte) { request.InputConnectionType = 3 }},
		{"output size", func(request *ForwardOpenRequest, _ *[]byte) { request.OutputApplicationSize = 506 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate, route := request, []byte(nil)
			test.mutate(&candidate, &route)
			if _, err := EncodeForwardOpen(candidate, route); err == nil {
				t.Fatal("accepted invalid request")
			}
		})
	}
}

func TestDecodeForwardOpenResponse(t *testing.T) {
	identity := ConnectionIdentity{ConnectionSerial: 0x1234, VendorID: 0x5678, OriginatorSerial: 0x9abcdef0}
	packet, _ := hex.DecodeString("d4000000443322118877665534127856f0debc9a204e0000204e00000000")
	response, err := DecodeForwardOpenResponse(packet, identity)
	if err != nil {
		t.Fatal(err)
	}
	if response.OTConnectionID != 0x11223344 || response.TOConnectionID != 0x55667788 || response.OTRPIMicroseconds != 20000 || response.TORPIMicroseconds != 20000 {
		t.Fatalf("response=%+v", response)
	}
	tests := []struct {
		name   string
		mutate func([]byte)
		want   string
	}{
		{"service", func(packet []byte) { packet[0] = 0xd5 }, "service"},
		{"reserved", func(packet []byte) { packet[1] = 1 }, "reserved"},
		{"status", func(packet []byte) { packet[2] = 1 }, "status"},
		{"additional", func(packet []byte) { packet[3] = 20 }, "additional"},
		{"identity", func(packet []byte) { packet[12]++ }, "identity"},
		{"ot api", func(packet []byte) { clear(packet[20:24]) }, "O->T API"},
		{"to api", func(packet []byte) { clear(packet[24:28]) }, "T->O API"},
		{"reply", func(packet []byte) { packet[28] = 1 }, "application reply"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := bytes.Clone(packet)
			test.mutate(candidate)
			if _, err := DecodeForwardOpenResponse(candidate, identity); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want containing %q", err, test.want)
			}
		})
	}
}

func TestForwardCloseGoldenAndResponse(t *testing.T) {
	identity := ConnectionIdentity{ConnectionSerial: 0x1234, VendorID: 0x5678, OriginatorSerial: 0x9abcdef0}
	packet, err := EncodeForwardClose(identity, []byte{1, 0}, nil, 100, 101)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("4e02200624010a0e34127856f0debc9a0400010020042c642c65")
	if !bytes.Equal(packet, want) {
		t.Fatalf("packet=%x, want %x", packet, want)
	}
	response, _ := hex.DecodeString("ce00000034127856f0debc9a0000")
	if err := DecodeForwardCloseResponse(response, identity); err != nil {
		t.Fatal(err)
	}
	response[4]++
	if err := DecodeForwardCloseResponse(response, identity); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("error=%v", err)
	}
}
