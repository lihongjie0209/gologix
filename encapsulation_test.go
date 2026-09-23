package gologix

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestRegisterSessionGolden(t *testing.T) {
	packet := EncodeRegisterSession(0x0102030405060708)
	want, err := hex.DecodeString("65000400000000000000000008070605040302010000000001000000")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet, want) {
		t.Fatalf("packet = %x, want %x", packet, want)
	}
	header, payload, err := DecodeEncapsulation(packet, EncapsulationCommandRegisterSession, 0, 0x0102030405060708)
	if err != nil {
		t.Fatal(err)
	}
	if header.Command != EncapsulationCommandRegisterSession || header.Length != 4 || header.Session != 0 || header.Status != 0 || header.Context != 0x0102030405060708 || header.Options != 0 || !bytes.Equal(payload, []byte{1, 0, 0, 0}) {
		t.Fatalf("header=%+v payload=%x", header, payload)
	}
	payload[0] = 2
	if packet[24] != 1 {
		t.Fatal("decoded payload aliases packet")
	}
}

func TestDecodeEncapsulationValidation(t *testing.T) {
	base := EncodeRegisterSession(9)
	tests := []struct {
		name    string
		mutate  func([]byte) []byte
		command uint16
		session uint32
		context uint64
		want    string
	}{
		{"short", func(packet []byte) []byte { return packet[:23] }, EncapsulationCommandRegisterSession, 0, 9, "short"},
		{"length", func(packet []byte) []byte { packet[2] = 5; return packet }, EncapsulationCommandRegisterSession, 0, 9, "length"},
		{"command", func(packet []byte) []byte { packet[0] = 0x66; return packet }, EncapsulationCommandRegisterSession, 0, 9, "command"},
		{"session", func(packet []byte) []byte { packet[4] = 1; return packet }, EncapsulationCommandRegisterSession, 0, 9, "session"},
		{"status", func(packet []byte) []byte { packet[8] = 1; return packet }, EncapsulationCommandRegisterSession, 0, 9, "status"},
		{"context", func(packet []byte) []byte { packet[12] = 8; return packet }, EncapsulationCommandRegisterSession, 0, 9, "context"},
		{"options", func(packet []byte) []byte { packet[20] = 1; return packet }, EncapsulationCommandRegisterSession, 0, 9, "options"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := DecodeEncapsulation(test.mutate(bytes.Clone(base)), test.command, test.session, test.context)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), test.want) {
				t.Fatalf("error=%v, want containing %q", err, test.want)
			}
		})
	}
}

func TestDecodeRegisterSessionResponse(t *testing.T) {
	packet := EncodeRegisterSession(11)
	copy(packet[4:8], []byte{0x78, 0x56, 0x34, 0x12})
	session, err := DecodeRegisterSessionResponse(packet, 11)
	if err != nil || session != 0x12345678 {
		t.Fatalf("session=%08x error=%v", session, err)
	}
	invalid := [][]byte{
		append(bytes.Clone(packet[:24]), 2, 0, 0, 0),
		append(bytes.Clone(packet[:24]), 1, 0, 1, 0),
		bytes.Clone(packet),
	}
	invalid[0][2], invalid[0][3] = 4, 0
	invalid[1][2], invalid[1][3] = 4, 0
	for index, candidate := range invalid {
		if index == 2 {
			candidate[4], candidate[5], candidate[6], candidate[7] = 0, 0, 0, 0
		}
		if _, err := DecodeRegisterSessionResponse(candidate, 11); err == nil {
			t.Fatalf("accepted invalid response %x", candidate)
		}
	}
}
