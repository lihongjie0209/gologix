package gologix

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func decodeTestHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestClass1SessionRegisterOpenClose(t *testing.T) {
	client, server := net.Pipe()
	serverErrors := make(chan error, 1)
	go func() {
		defer close(serverErrors)
		defer func() { _ = server.Close() }()
		request, err := ReadEncapsulationFrame(server)
		if err != nil {
			serverErrors <- err
			return
		}
		if _, _, err = DecodeEncapsulation(request, EncapsulationCommandRegisterSession, 0, 1); err != nil {
			serverErrors <- err
			return
		}
		response := EncodeRegisterSession(1)
		binary.LittleEndian.PutUint32(response[4:8], 0x12345678)
		if _, err = server.Write(response); err != nil {
			serverErrors <- err
			return
		}

		request, err = ReadEncapsulationFrame(server)
		if err != nil {
			serverErrors <- err
			return
		}
		cip, _, err := DecodeSendRRData(request, 0x12345678, 2)
		if err != nil || len(cip) == 0 || cip[0] != byte(CIPService_ForwardOpen) {
			serverErrors <- errors.New("invalid Forward Open request")
			return
		}
		openResponse := decodeTestHex(t, "d4000000443322118877665534127856f0debc9a204e0000204e00000000")
		response, err = EncodeSendRRData(0x12345678, 0, 2, openResponse, SendRRDataAddresses{})
		if err != nil {
			serverErrors <- err
			return
		}
		if _, err = server.Write(response); err != nil {
			serverErrors <- err
			return
		}

		request, err = ReadEncapsulationFrame(server)
		if err != nil {
			serverErrors <- err
			return
		}
		cip, _, err = DecodeSendRRData(request, 0x12345678, 3)
		if err != nil || len(cip) == 0 || cip[0] != byte(CIPService_ForwardClose) {
			serverErrors <- errors.New("invalid Forward Close request")
			return
		}
		closeResponse := decodeTestHex(t, "ce00000034127856f0debc9a0000")
		response, err = EncodeSendRRData(0x12345678, 0, 3, closeResponse, SendRRDataAddresses{})
		if err != nil {
			serverErrors <- err
			return
		}
		if _, err = server.Write(response); err != nil {
			serverErrors <- err
		}
	}()

	session, err := NewClass1Session(client, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err = session.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	configuration := uint16(3)
	identity := ConnectionIdentity{ConnectionSerial: 0x1234, VendorID: 0x5678, OriginatorSerial: 0x9abcdef0}
	opened, err := session.ForwardOpen(context.Background(), ForwardOpenRequest{
		OTConnectionID: 0x11223344, TOConnectionID: 0x55667788, Identity: identity,
		TimeoutMultiplier: 4, RPIMicroseconds: 20000, Priority: Class1PriorityScheduled,
		InputConnectionType:   Class1ConnectionPointToPoint,
		ConfigurationAssembly: &configuration, OutputAssembly: 100, InputAssembly: 101,
		OutputApplicationSize: 8, InputApplicationSize: 16,
	}, []byte{1, 0}, SendRRDataAddresses{})
	if err != nil {
		t.Fatal(err)
	}
	if opened.OTConnectionID != 0x11223344 || opened.TOConnectionID != 0x55667788 {
		t.Fatalf("opened=%+v", opened)
	}
	if err = session.ForwardClose(context.Background(), identity, []byte{1, 0}, &configuration, 100, 101); err != nil {
		t.Fatal(err)
	}
	if err = session.Close(); err != nil {
		t.Fatal(err)
	}
	if err = session.Close(); err != nil {
		t.Fatal(err)
	}
	for err = range serverErrors {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestClass1SessionCancellationInvalidatesWithoutReplay(t *testing.T) {
	client, server := net.Pipe()
	requests := make(chan int, 1)
	release := make(chan struct{})
	go func() {
		defer func() { _ = server.Close() }()
		if _, err := ReadEncapsulationFrame(server); err == nil {
			requests <- 1
			<-release
		}
	}()
	session, err := NewClass1Session(client, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err = session.Register(ctx)
	close(release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	if session.Failure() == nil {
		t.Fatal("session was not invalidated")
	}
	if count := <-requests; count != 1 {
		t.Fatalf("requests=%d", count)
	}
	if err = session.Register(context.Background()); err == nil {
		t.Fatal("unusable session accepted another operation")
	}
	_ = session.Close()
}

func TestNewClass1SessionValidation(t *testing.T) {
	if _, err := NewClass1Session(nil, time.Second); err == nil {
		t.Fatal("accepted nil connection")
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if _, err := NewClass1Session(client, 0); err == nil {
		t.Fatal("accepted nonpositive timeout")
	}
}

func TestReadEncapsulationFrameRejectsTruncation(t *testing.T) {
	header := make([]byte, EncapsulationHeaderSize)
	binary.LittleEndian.PutUint16(header[2:4], 2)
	packet := append(header, byte(1))
	if _, err := ReadEncapsulationFrame(&shortReader{data: packet}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error=%v", err)
	}
}

type shortReader struct{ data []byte }

func (r *shortReader) Read(buffer []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(buffer, r.data)
	r.data = r.data[n:]
	return n, nil
}
