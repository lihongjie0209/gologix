package gologix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type Class1Session struct {
	mu          sync.Mutex
	connection  net.Conn
	timeout     time.Duration
	session     uint32
	nextContext uint64
	failure     error
	closed      bool
}

func NewClass1Session(connection net.Conn, timeout time.Duration) (*Class1Session, error) {
	if connection == nil {
		return nil, errors.New("Class 1 session connection is required")
	}
	if timeout <= 0 {
		return nil, errors.New("Class 1 session timeout must be positive")
	}
	return &Class1Session{connection: connection, timeout: timeout}, nil
}

func (s *Class1Session) Register(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("registering Class 1 session: connection is closed")
	}
	if s.failure != nil {
		return fmt.Errorf("Class 1 session is unusable after exchange failure: %w", s.failure)
	}
	if s.session != 0 {
		return errors.New("Class 1 session is already registered")
	}
	contextID := s.advanceContext()
	response, err := s.exchangeLocked(ctx, EncodeRegisterSession(contextID))
	if err != nil {
		s.failure = err
		return fmt.Errorf("registering Class 1 session: %w", err)
	}
	session, err := DecodeRegisterSessionResponse(response, contextID)
	if err != nil {
		s.failure = err
		return err
	}
	s.session = session
	return nil
}

func (s *Class1Session) ForwardOpen(ctx context.Context, request ForwardOpenRequest, route []byte, addresses SendRRDataAddresses) (ForwardOpenResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.registeredLocked(); err != nil {
		return ForwardOpenResponse{}, err
	}
	cip, err := EncodeForwardOpen(request, route)
	if err != nil {
		return ForwardOpenResponse{}, err
	}
	contextID := s.advanceContext()
	packet, err := EncodeSendRRData(s.session, 0, contextID, cip, addresses)
	if err != nil {
		return ForwardOpenResponse{}, err
	}
	response, err := s.exchangeLocked(ctx, packet)
	if err != nil {
		s.failure = err
		return ForwardOpenResponse{}, fmt.Errorf("sending Forward Open: %w", err)
	}
	responseCIP, responseAddresses, err := DecodeSendRRData(response, s.session, contextID)
	if err != nil {
		s.failure = err
		return ForwardOpenResponse{}, err
	}
	result, err := DecodeForwardOpenResponse(responseCIP, request.Identity)
	if err != nil {
		s.failure = err
		return ForwardOpenResponse{}, err
	}
	result.SocketAddresses = responseAddresses
	return result, nil
}

func (s *Class1Session) ForwardClose(ctx context.Context, identity ConnectionIdentity, route []byte, configuration *uint16, output, input uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.registeredLocked(); err != nil {
		return err
	}
	cip, err := EncodeForwardClose(identity, route, configuration, output, input)
	if err != nil {
		return err
	}
	contextID := s.advanceContext()
	packet, err := EncodeSendRRData(s.session, 0, contextID, cip, SendRRDataAddresses{})
	if err != nil {
		return err
	}
	response, err := s.exchangeLocked(ctx, packet)
	if err != nil {
		s.failure = err
		return fmt.Errorf("sending Forward Close: %w", err)
	}
	responseCIP, _, err := DecodeSendRRData(response, s.session, contextID)
	if err != nil {
		s.failure = err
		return err
	}
	if err = DecodeForwardCloseResponse(responseCIP, identity); err != nil {
		s.failure = err
	}
	return err
}

func (s *Class1Session) Failure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failure
}

func (s *Class1Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.connection.Close()
}

func (s *Class1Session) registeredLocked() error {
	if s.closed {
		return errors.New("using Class 1 session: connection is closed")
	}
	if s.failure != nil {
		return fmt.Errorf("Class 1 session is unusable after exchange failure: %w", s.failure)
	}
	if s.session == 0 {
		return errors.New("Class 1 session is not registered")
	}
	return nil
}

func (s *Class1Session) advanceContext() uint64 {
	s.nextContext++
	if s.nextContext == 0 {
		s.nextContext++
	}
	return s.nextContext
}

func (s *Class1Session) exchangeLocked(ctx context.Context, request []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(s.timeout)
	contextDeadlineSelected := false
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
		contextDeadlineSelected = true
	}
	if err := s.connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = s.connection.SetDeadline(time.Now()) })
	defer func() {
		stop()
		_ = s.connection.SetDeadline(time.Time{})
	}()
	if err := WriteEncapsulationFrame(s.connection, request); err != nil {
		if contextErr := contextIOError(ctx, err, deadline, contextDeadlineSelected); contextErr != nil {
			return nil, contextErr
		}
		return nil, err
	}
	response, err := ReadEncapsulationFrame(s.connection)
	if err != nil {
		if contextErr := contextIOError(ctx, err, deadline, contextDeadlineSelected); contextErr != nil {
			return nil, contextErr
		}
		return nil, err
	}
	return response, nil
}

func contextIOError(ctx context.Context, ioErr error, deadline time.Time, contextDeadlineSelected bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var netErr net.Error
	if contextDeadlineSelected && errors.As(ioErr, &netErr) && netErr.Timeout() && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// WriteEncapsulationFrame writes one already encoded packet completely.
func WriteEncapsulationFrame(writer io.Writer, packet []byte) error {
	if writer == nil {
		return io.ErrClosedPipe
	}
	for len(packet) > 0 {
		written, err := writer.Write(packet)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		packet = packet[written:]
	}
	return nil
}

// ReadEncapsulationFrame reads one complete bounded encapsulation packet.
func ReadEncapsulationFrame(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, io.ErrClosedPipe
	}
	header := make([]byte, EncapsulationHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := int(header[2]) | int(header[3])<<8
	packet := make([]byte, EncapsulationHeaderSize+length)
	copy(packet, header)
	if _, err := io.ReadFull(reader, packet[EncapsulationHeaderSize:]); err != nil {
		return nil, err
	}
	return packet, nil
}
