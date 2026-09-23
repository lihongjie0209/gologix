package gologix

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

type Class1SequenceTracker struct {
	initialized bool
	last        uint32
}

func (t *Class1SequenceTracker) Accept(sequence uint32) (bool, uint32) {
	if !t.initialized {
		t.initialized = true
		t.last = sequence
		return true, 0
	}
	distance := sequence - t.last
	if distance == 0 || distance >= 1<<31 {
		return false, 0
	}
	t.last = sequence
	return true, distance - 1
}

type Class1UDPTransport struct {
	connection     *net.UDPConn
	maxPacketBytes int
}

func NewClass1UDPTransport(connection *net.UDPConn, maxPacketBytes int) (*Class1UDPTransport, error) {
	if connection == nil {
		return nil, errors.New("Class 1 UDP connection is required")
	}
	if maxPacketBytes < 1 {
		return nil, errors.New("Class 1 UDP packet bound must be positive")
	}
	return &Class1UDPTransport{connection: connection, maxPacketBytes: maxPacketBytes}, nil
}

func (t *Class1UDPTransport) Read(ctx context.Context, expectedSource *net.UDPAddr, connectionID uint32, applicationSize int, runIdleHeader bool) (Class1Packet, *net.UDPAddr, error) {
	if !validIPv4UDPAddress(expectedSource) {
		return Class1Packet{}, nil, errors.New("Class 1 input requires a valid expected IPv4 source")
	}
	if err := ctx.Err(); err != nil {
		return Class1Packet{}, nil, err
	}
	deadline, contextDeadlineSelected := ctx.Deadline()
	if err := setUDPDeadline(t.connection.SetReadDeadline, deadline, contextDeadlineSelected); err != nil {
		return Class1Packet{}, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = t.connection.SetReadDeadline(time.Now()) })
	defer func() {
		stop()
		_ = t.connection.SetReadDeadline(time.Time{})
	}()
	buffer := make([]byte, t.maxPacketBytes+1)
	for {
		length, source, err := t.connection.ReadFromUDP(buffer)
		if err != nil {
			if contextErr := contextIOError(ctx, err, deadline, contextDeadlineSelected); contextErr != nil {
				return Class1Packet{}, nil, contextErr
			}
			return Class1Packet{}, nil, err
		}
		if !sameUDPAddress(source, expectedSource) {
			continue
		}
		if length > t.maxPacketBytes {
			return Class1Packet{}, source, fmt.Errorf("Class 1 input packet exceeds %d bytes", t.maxPacketBytes)
		}
		packet, err := DecodeClass1CPF(buffer[:length], connectionID, applicationSize, runIdleHeader)
		if err != nil {
			return Class1Packet{}, source, err
		}
		return packet, cloneUDPAddress(source), nil
	}
}

func (t *Class1UDPTransport) Write(ctx context.Context, destination *net.UDPAddr, connectionID, sequence uint32, data []byte, runIdleHeader, run bool) error {
	if !validIPv4UDPAddress(destination) {
		return errors.New("Class 1 output requires a valid IPv4 destination")
	}
	packet, err := EncodeClass1CPF(connectionID, sequence, data, runIdleHeader, run)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	deadline, contextDeadlineSelected := ctx.Deadline()
	if err = setUDPDeadline(t.connection.SetWriteDeadline, deadline, contextDeadlineSelected); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = t.connection.SetWriteDeadline(time.Now()) })
	defer func() {
		stop()
		_ = t.connection.SetWriteDeadline(time.Time{})
	}()
	written, err := t.connection.WriteToUDP(packet, destination)
	if err != nil {
		if contextErr := contextIOError(ctx, err, deadline, contextDeadlineSelected); contextErr != nil {
			return contextErr
		}
		return err
	}
	if written != len(packet) {
		return fmt.Errorf("Class 1 output wrote %d of %d bytes", written, len(packet))
	}
	return nil
}

func setUDPDeadline(set func(time.Time) error, deadline time.Time, ok bool) error {
	if !ok {
		return set(time.Time{})
	}
	return set(deadline)
}

func validIPv4UDPAddress(address *net.UDPAddr) bool {
	return address != nil && address.IP.To4() != nil && address.Port > 0 && address.Port <= 65535
}

func sameUDPAddress(left, right *net.UDPAddr) bool {
	return left != nil && right != nil && left.Port == right.Port && left.Zone == right.Zone && left.IP.Equal(right.IP)
}

func cloneUDPAddress(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}
