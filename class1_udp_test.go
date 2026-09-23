package gologix

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestClass1SequenceTracker(t *testing.T) {
	tracker := Class1SequenceTracker{}
	for _, test := range []struct {
		sequence uint32
		accepted bool
		gap      uint32
	}{{10, true, 0}, {10, false, 0}, {9, false, 0}, {12, true, 1}, {11, false, 0}, {0xffffffff, false, 0}} {
		accepted, gap := tracker.Accept(test.sequence)
		if accepted != test.accepted || gap != test.gap {
			t.Fatalf("sequence=%d accepted=%v gap=%d, want %v/%d", test.sequence, accepted, gap, test.accepted, test.gap)
		}
	}
	wrap := Class1SequenceTracker{}
	wrap.Accept(0xfffffffe)
	if accepted, gap := wrap.Accept(1); !accepted || gap != 2 {
		t.Fatalf("wrap accepted=%v gap=%d", accepted, gap)
	}
}

func TestClass1UDPTransportLoopback(t *testing.T) {
	receiver := listenClass1UDP(t)
	sender := listenClass1UDP(t)
	transport, err := NewClass1UDPTransport(receiver, 128)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := EncodeClass1CPF(0x12345678, 9, []byte{1, 2, 3}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sender.WriteToUDP(payload, receiver.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	packet, source, err := transport.Read(context.Background(), sender.LocalAddr().(*net.UDPAddr), 0x12345678, 3, false)
	if err != nil || packet.Sequence != 9 || !bytes.Equal(packet.Data, []byte{1, 2, 3}) || source.String() != sender.LocalAddr().String() {
		t.Fatalf("packet=%+v source=%v error=%v", packet, source, err)
	}
	if err = transport.Write(context.Background(), sender.LocalAddr().(*net.UDPAddr), 7, 11, []byte{4, 5}, true, true); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	_ = sender.SetReadDeadline(time.Now().Add(time.Second))
	n, source, err := sender.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeClass1CPF(buffer[:n], 7, 2, true)
	if err != nil || decoded.Sequence != 11 || !decoded.Run || source.String() != receiver.LocalAddr().String() {
		t.Fatalf("packet=%+v source=%v error=%v", decoded, source, err)
	}
}

func TestClass1UDPTransportSourceCancellationAndBounds(t *testing.T) {
	receiver := listenClass1UDP(t)
	expected := listenClass1UDP(t)
	unexpected := listenClass1UDP(t)
	transport, err := NewClass1UDPTransport(receiver, 32)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := EncodeClass1CPF(7, 1, []byte{1}, false, false)
	right, _ := EncodeClass1CPF(7, 2, []byte{2}, false, false)
	_, _ = unexpected.WriteToUDP(wrong, receiver.LocalAddr().(*net.UDPAddr))
	_, _ = expected.WriteToUDP(right, receiver.LocalAddr().(*net.UDPAddr))
	packet, _, err := transport.Read(context.Background(), expected.LocalAddr().(*net.UDPAddr), 7, 1, false)
	if err != nil || packet.Sequence != 2 {
		t.Fatalf("packet=%+v error=%v", packet, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err = transport.Read(ctx, expected.LocalAddr().(*net.UDPAddr), 7, 1, false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	if err = transport.Write(context.Background(), expected.LocalAddr().(*net.UDPAddr), 1, 1, make([]byte, 505), false, false); err == nil {
		t.Fatal("accepted oversized output")
	}
	if _, err = NewClass1UDPTransport(nil, 32); err == nil {
		t.Fatal("accepted nil socket")
	}
}

func listenClass1UDP(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}
