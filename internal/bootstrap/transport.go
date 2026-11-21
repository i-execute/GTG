package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

type Transport uint8

const (
	Abridged Transport = iota
	Intermediate
	PaddedIntermediate
)

var ErrTransport = errors.New("gtg: bootstrap transport rejected")

type Connection struct {
	connection net.Conn
	transport  Transport
}

func Dial(ctx context.Context, address string, transport Transport) (*Connection, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	result := &Connection{connection: connection, transport: transport}
	if err := result.writeOpening(); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return result, nil
}

func (x *Connection) Close() error {
	if x == nil || x.connection == nil {
		return nil
	}
	return x.connection.Close()
}

func (x *Connection) SetDeadline(deadline time.Time) error {
	if x == nil || x.connection == nil {
		return ErrTransport
	}
	return x.connection.SetDeadline(deadline)
}

func (x *Connection) WritePacket(packet []byte) error {
	if x == nil || x.connection == nil || len(packet) == 0 || len(packet) > 1<<20 || len(packet)&3 != 0 {
		return ErrTransport
	}
	switch x.transport {
	case Abridged:
		return x.writeAbridged(packet)
	case Intermediate:
		return x.writeIntermediate(packet, false)
	case PaddedIntermediate:
		return x.writeIntermediate(packet, true)
	default:
		return ErrTransport
	}
}

func (x *Connection) ReadPacket() ([]byte, error) {
	if x == nil || x.connection == nil {
		return nil, ErrTransport
	}
	switch x.transport {
	case Abridged:
		return x.readAbridged()
	case Intermediate, PaddedIntermediate:
		return x.readIntermediate()
	default:
		return nil, ErrTransport
	}
}

func (x *Connection) writeOpening() error {
	switch x.transport {
	case Abridged:
		return writeAll(x.connection, []byte{0xef})
	case Intermediate:
		var opening [4]byte
		binary.LittleEndian.PutUint32(opening[:], 0xeeeeeeee)
		return writeAll(x.connection, opening[:])
	case PaddedIntermediate:
		var opening [4]byte
		binary.LittleEndian.PutUint32(opening[:], 0xdddddddd)
		return writeAll(x.connection, opening[:])
	default:
		return ErrTransport
	}
}

func (x *Connection) writeAbridged(packet []byte) error {
	words := len(packet) >> 2
	if words >= 1<<24 {
		return ErrTransport
	}
	if words < 0x7f {
		if err := writeAll(x.connection, []byte{byte(words)}); err != nil {
			return err
		}
	} else {
		header := []byte{0x7f, byte(words), byte(words >> 8), byte(words >> 16)}
		if err := writeAll(x.connection, header); err != nil {
			return err
		}
	}
	return writeAll(x.connection, packet)
}

func (x *Connection) writeIntermediate(packet []byte, padded bool) error {
	body := packet
	if padded {
		padding := make([]byte, int(time.Now().UnixNano()%16))
		if len(padding) != 0 {
			if _, err := io.ReadFull(rand.Reader, padding); err != nil {
				return err
			}
			body = append(append([]byte(nil), packet...), padding...)
		}
	}
	if len(body) == 0 || len(body) > 1<<20 {
		return ErrTransport
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(body)))
	if err := writeAll(x.connection, header[:]); err != nil {
		return err
	}
	return writeAll(x.connection, body)
}

func (x *Connection) readAbridged() ([]byte, error) {
	var first [1]byte
	if _, err := io.ReadFull(x.connection, first[:]); err != nil {
		return nil, err
	}
	words := int(first[0])
	if words == 0x7f {
		var length [3]byte
		if _, err := io.ReadFull(x.connection, length[:]); err != nil {
			return nil, err
		}
		words = int(length[0]) | int(length[1])<<8 | int(length[2])<<16
	}
	if words == 0 || words > 1<<18 {
		return nil, ErrTransport
	}
	packet := make([]byte, words*4)
	if _, err := io.ReadFull(x.connection, packet); err != nil {
		clear(packet)
		return nil, err
	}
	return packet, nil
}

func (x *Connection) readIntermediate() ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(x.connection, header[:]); err != nil {
		return nil, err
	}
	value := binary.LittleEndian.Uint32(header[:])
	if value&0x80000000 != 0 {
		return append([]byte(nil), header[:]...), nil
	}
	length := int(value)
	if length == 0 || length > 1<<20 {
		return nil, ErrTransport
	}
	packet := make([]byte, length)
	if _, err := io.ReadFull(x.connection, packet); err != nil {
		clear(packet)
		return nil, err
	}
	return packet, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count <= 0 || count > len(data) {
			return ErrTransport
		}
		data = data[count:]
	}
	return nil
}
