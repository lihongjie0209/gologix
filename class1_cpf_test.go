package gologix

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEncodeClass1CPF(t *testing.T) {
	packet, err := EncodeClass1CPF(0x11223344, 0x55667788, []byte{0xaa, 0xbb}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("0200028008004433221188776655b1000800887701000000aabb")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet, want) {
		t.Fatalf("packet = %x, want %x", packet, want)
	}

	decoded, err := DecodeClass1CPF(packet, 0x11223344, 2, true)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Sequence != 0x55667788 || decoded.TransportSequence != 0x7788 || !decoded.Run || !bytes.Equal(decoded.Data, []byte{0xaa, 0xbb}) {
		t.Fatalf("decoded = %+v", decoded)
	}
	decoded.Data[0] = 0
	if packet[len(packet)-2] != 0xaa {
		t.Fatal("decoded data aliases packet")
	}
}

func TestClass1CPFWithoutRunIdle(t *testing.T) {
	packet, err := EncodeClass1CPF(7, 8, []byte{1, 2, 3}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeClass1CPF(packet, 7, 3, false)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Run || !bytes.Equal(decoded.Data, []byte{1, 2, 3}) {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestClass1CPFRejectsInvalidInput(t *testing.T) {
	if _, err := EncodeClass1CPF(0, 1, nil, false, false); err == nil {
		t.Fatal("accepted zero connection ID")
	}
	if _, err := EncodeClass1CPF(1, 1, make([]byte, 505), false, false); err == nil {
		t.Fatal("accepted oversized application data")
	}
	valid, err := EncodeClass1CPF(7, 8, []byte{1, 2}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "short", mutate: func(packet []byte) []byte { return packet[:len(packet)-1] }},
		{name: "item count", mutate: func(packet []byte) []byte { packet[0] = 3; return packet }},
		{name: "address type", mutate: func(packet []byte) []byte { packet[2] = 1; return packet }},
		{name: "address length", mutate: func(packet []byte) []byte { packet[4] = 7; return packet }},
		{name: "connection", mutate: func(packet []byte) []byte { packet[6] = 8; return packet }},
		{name: "data type", mutate: func(packet []byte) []byte { packet[14] = 0xb2; return packet }},
		{name: "data length", mutate: func(packet []byte) []byte { packet[16]++; return packet }},
		{name: "transport sequence", mutate: func(packet []byte) []byte { packet[18]++; return packet }},
		{name: "run idle reserved", mutate: func(packet []byte) []byte { packet[20] = 2; return packet }},
		{name: "trailing", mutate: func(packet []byte) []byte { return append(packet, 0) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := test.mutate(bytes.Clone(valid))
			if _, err := DecodeClass1CPF(candidate, 7, 2, true); err == nil {
				t.Fatal("accepted malformed packet")
			}
		})
	}
	if _, err := DecodeClass1CPF(valid, 0, 2, true); err == nil {
		t.Fatal("accepted zero expected connection ID")
	}
	if _, err := DecodeClass1CPF(valid, 7, 505, true); err == nil {
		t.Fatal("accepted oversized expected application data")
	}
}
