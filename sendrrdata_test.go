package gologix

import (
	"bytes"
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

func TestSendRRDataGolden(t *testing.T) {
	addresses := SendRRDataAddresses{
		OT: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 2222},
		TO: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 2222},
	}
	packet, err := EncodeSendRRData(0x12345678, 0, 10, []byte{0x54, 0}, addresses)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("6f003a0078563412000000000a0000000000000000000000000000000000040000000000b2000200540000801000000208aec000020a000000000000000001801000000208aec00002140000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet, want) {
		t.Fatalf("packet = %x, want %x", packet, want)
	}
	cip, decoded, err := DecodeSendRRData(packet, 0x12345678, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cip, []byte{0x54, 0}) || decoded.OT.String() != "192.0.2.10:2222" || decoded.TO.String() != "192.0.2.20:2222" {
		t.Fatalf("cip=%x addresses=%+v", cip, decoded)
	}
	cip[0] = 0
	decoded.OT.IP[0] = 1
	if packet[40] != 0x54 || packet[50] != 192 {
		t.Fatal("decoded values alias encoded packet")
	}
}

func TestSendRRDataWithoutSocketAddresses(t *testing.T) {
	packet, err := EncodeSendRRData(0x12345678, 0, 10, []byte{0x54, 0}, SendRRDataAddresses{})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("6f00120078563412000000000a0000000000000000000000000000000000020000000000b20002005400")
	if !bytes.Equal(packet, want) {
		t.Fatalf("packet = %x, want %x", packet, want)
	}
	if cip, addresses, err := DecodeSendRRData(packet, 0x12345678, 10); err != nil || !bytes.Equal(cip, []byte{0x54, 0}) || addresses.OT != nil || addresses.TO != nil {
		t.Fatalf("cip=%x addresses=%+v error=%v", cip, addresses, err)
	}
}

func TestSendRRDataValidation(t *testing.T) {
	addresses := SendRRDataAddresses{TO: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 2222}}
	valid, err := EncodeSendRRData(1, 0, 2, []byte{0xd4, 0, 0, 0}, addresses)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func([]byte) []byte
		want   string
	}{
		{"short header", func(packet []byte) []byte { return packet[:23] }, "header"},
		{"length", func(packet []byte) []byte { packet[2]++; return packet }, "length"},
		{"command", func(packet []byte) []byte { packet[0] = 0x65; return packet }, "command"},
		{"session", func(packet []byte) []byte { packet[4]++; return packet }, "session"},
		{"status", func(packet []byte) []byte { packet[8] = 1; return packet }, "status"},
		{"context", func(packet []byte) []byte { packet[12]++; return packet }, "context"},
		{"options", func(packet []byte) []byte { packet[20] = 1; return packet }, "options"},
		{"interface", func(packet []byte) []byte { packet[24] = 1; return packet }, "interface"},
		{"timeout", func(packet []byte) []byte { packet[28] = 1; return packet }, "timeout"},
		{"count", func(packet []byte) []byte { packet[30] = 5; return packet }, "item count"},
		{"null type", func(packet []byte) []byte { packet[32] = 1; return packet }, "null address"},
		{"null length", func(packet []byte) []byte { packet[34] = 1; return packet }, "null address"},
		{"data type", func(packet []byte) []byte { packet[36] = 0xb1; return packet }, "unconnected data"},
		{"data length", func(packet []byte) []byte { packet[38]++; return packet }, "length"},
		{"socket type", func(packet []byte) []byte { packet[44] = 2; return packet }, "type"},
		{"socket length", func(packet []byte) []byte { packet[46] = 15; return packet }, "length"},
		{"family", func(packet []byte) []byte { packet[48], packet[49] = 0, 10; return packet }, "family"},
		{"port", func(packet []byte) []byte { packet[50], packet[51] = 0, 0; return packet }, "port"},
		{"reserved", func(packet []byte) []byte { packet[56] = 1; return packet }, "reserved"},
		{"trailing", func(packet []byte) []byte { packet = append(packet, 0); packet[2]++; return packet }, "item count"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := DecodeSendRRData(test.mutate(bytes.Clone(valid)), 1, 2); err == nil || !strings.Contains(strings.ToLower(err.Error()), test.want) {
				t.Fatalf("error=%v, want containing %q", err, test.want)
			}
		})
	}
	if _, err := EncodeSendRRData(1, 0, 2, make([]byte, 65520), SendRRDataAddresses{}); err == nil {
		t.Fatal("accepted oversized CIP data")
	}
	for _, address := range []*net.UDPAddr{
		{IP: net.ParseIP("2001:db8::1"), Port: 2222},
		{IP: net.IPv4(192, 0, 2, 1), Port: 0},
	} {
		if _, err := EncodeSendRRData(1, 0, 2, nil, SendRRDataAddresses{TO: address}); err == nil {
			t.Fatalf("accepted invalid address %+v", address)
		}
	}
}
