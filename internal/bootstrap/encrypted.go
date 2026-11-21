package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/i-execute/GTG/internal/tlgen"
)

const (
	constructorPingDelayDisconnect uint32 = 0xf3427b8c
	constructorPong                uint32 = 0x347773c5
	constructorMessageContainer    uint32 = 0x73f1f8dc
)

var ErrEncrypted = errors.New("gtg: bootstrap encrypted exchange failed")

type EncryptedSession struct {
	mu         sync.Mutex
	connection *Connection
	box        *legacyMTProto
	salt       [8]byte
	sessionID  [8]byte
	offset     int64
	messages   messageIDs
	sequence   uint32
}

func DialExistingAuth(ctx context.Context, endpoint string, transport Transport, authKey []byte, serverSalt [8]byte, timeOffset int64) (*EncryptedSession, error) {
	return DialEncrypted(ctx, AuthResult{AuthKey: authKey, ServerSalt: serverSalt, TimeOffset: timeOffset, Endpoint: endpoint, Transport: transport})
}

func DialEncrypted(ctx context.Context, result AuthResult) (*EncryptedSession, error) {
	if len(result.AuthKey) != 256 || result.Endpoint == "" {
		return nil, ErrEncrypted
	}
	connection := result.connection
	var err error
	if connection == nil {
		connection, err = Dial(ctx, result.Endpoint, result.Transport)
		if err != nil {
			return nil, err
		}
	}
	box, err := newLegacyMTProto(result.AuthKey)
	if err != nil {
		_ = connection.Close()
		return nil, ErrEncrypted
	}
	result.connection = nil
	out := &EncryptedSession{connection: connection, box: box, salt: result.ServerSalt, offset: result.TimeOffset}
	if _, err := io.ReadFull(rand.Reader, out.sessionID[:]); err != nil {
		out.Close()
		return nil, ErrEncrypted
	}
	if out.sessionID == [8]byte{} {
		out.sessionID[0] = 1
	}
	deadline := time.Now().Add(20 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if err := connection.SetDeadline(deadline); err != nil {
		out.Close()
		return nil, err
	}
	return out, nil
}

func (x *EncryptedSession) Close() error {
	if x == nil {
		return nil
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.box != nil {
		x.box.destroy()
		x.box = nil
	}
	clear(x.sessionID[:])
	clear(x.salt[:])
	if x.connection != nil {
		err := x.connection.Close()
		x.connection = nil
		return err
	}
	return nil
}

func (x *EncryptedSession) Ping(pingID uint64) error {
	if x == nil || pingID == 0 {
		return ErrEncrypted
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.connection == nil || x.box == nil {
		return ErrEncrypted
	}
	body := make([]byte, 16)
	binary.LittleEndian.PutUint32(body[:4], constructorPingDelayDisconnect)
	binary.LittleEndian.PutUint64(body[4:12], pingID)
	binary.LittleEndian.PutUint32(body[12:16], 30)
	if _, err := x.write(body, true); err != nil {
		return err
	}
	for index := 0; index < 8; index++ {
		body, err := x.read()
		if err != nil {
			return err
		}
		matched := containsPong(body, pingID)
		clear(body)
		if matched {
			return nil
		}
	}
	return ErrEncrypted
}

func (x *EncryptedSession) Exchange(ctx context.Context, body []byte) (uint64, [][]byte, error) {
	if x == nil || len(body) < 4 {
		return 0, nil, ErrEncrypted
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.connection == nil || x.box == nil {
		return 0, nil, ErrEncrypted
	}
	deadline := time.Now().Add(30 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if err := x.connection.SetDeadline(deadline); err != nil {
		return 0, nil, err
	}
	request := append([]byte(nil), body...)
	defer clear(request)
	requestID := uint64(0)
	for retry := 0; retry < 2; retry++ {
		work := append([]byte(nil), request...)
		var err error
		requestID, err = x.write(work, true)
		if err != nil {
			return 0, nil, err
		}
		for attempts := 0; attempts < 8; attempts++ {
			response, err := x.read()
			if err != nil {
				return requestID, nil, err
			}
			messages := unpackMessages(response)
			clear(response)
			if len(messages) == 0 {
				continue
			}
			if x.acceptSalt(messages) {
				clearMessages(messages)
				break
			}
			return requestID, messages, nil
		}
	}
	return requestID, nil, ErrEncrypted
}

func (x *EncryptedSession) write(body []byte, contentRelated bool) (uint64, error) {
	if len(body) < 4 || len(body)&3 != 0 || len(body) > 1<<20 {
		return 0, ErrEncrypted
	}
	payload := make([]byte, 32+len(body))
	copy(payload[:8], x.salt[:])
	copy(payload[8:16], x.sessionID[:])
	messageID := x.messages.next(time.Now().Add(time.Duration(x.offset) * time.Second))
	binary.LittleEndian.PutUint64(payload[16:24], messageID)
	sequence := x.sequence * 2
	if contentRelated {
		sequence++
		x.sequence++
	}
	binary.LittleEndian.PutUint32(payload[24:28], sequence)
	binary.LittleEndian.PutUint32(payload[28:32], uint32(len(body)))
	copy(payload[32:], body)
	clear(body)
	packet, err := x.box.seal(payload, true)
	clear(payload)
	if err != nil {
		return 0, ErrEncrypted
	}
	err = x.connection.WritePacket(packet)
	clear(packet)
	if err != nil {
		return 0, err
	}
	return messageID, nil
}

func (x *EncryptedSession) read() ([]byte, error) {
	for skips := 0; skips < 8; skips++ {
		packet, err := x.connection.ReadPacket()
		if err != nil {
			return nil, err
		}
		if len(packet) < 24 {
			clear(packet)
			continue
		}
		plain, err := x.box.open(packet, true)
		clear(packet)
		if err != nil || len(plain) < 36 {
			clear(plain)
			return nil, ErrEncrypted
		}
		if binary.LittleEndian.Uint64(plain[8:16]) != binary.LittleEndian.Uint64(x.sessionID[:]) {
			clear(plain)
			return nil, ErrEncrypted
		}
		length := int(binary.LittleEndian.Uint32(plain[28:32]))
		if length < 4 || length&3 != 0 || length > len(plain)-32 {
			clear(plain)
			return nil, ErrEncrypted
		}
		body := append([]byte(nil), plain[32:32+length]...)
		clear(plain)
		return body, nil
	}
	return nil, ErrEncrypted
}

func (x *EncryptedSession) acceptSalt(messages [][]byte) bool {
	updated := false
	schema := tlgen.Schema()
	for _, message := range messages {
		value, unknown, err := schema.Decode(message)
		if err != nil || unknown != nil || value.Name != "bad_server_salt" {
			continue
		}
		salt, ok := value.Fields["new_server_salt"].(int64)
		if !ok {
			continue
		}
		binary.LittleEndian.PutUint64(x.salt[:], uint64(salt))
		updated = true
	}
	return updated
}

func unpackMessages(body []byte) [][]byte {
	if len(body) < 8 || binary.LittleEndian.Uint32(body[:4]) != constructorMessageContainer {
		return [][]byte{append([]byte(nil), body...)}
	}
	count := int(binary.LittleEndian.Uint32(body[4:8]))
	if count < 0 || count > 64 {
		return nil
	}
	offset := 8
	result := make([][]byte, 0, count)
	for index := 0; index < count; index++ {
		if len(body)-offset < 16 {
			clearMessages(result)
			return nil
		}
		length := int(binary.LittleEndian.Uint32(body[offset+12 : offset+16]))
		if length < 4 || length&3 != 0 || len(body)-offset-16 < length {
			clearMessages(result)
			return nil
		}
		result = append(result, append([]byte(nil), body[offset+16:offset+16+length]...))
		offset += 16 + length
	}
	if offset != len(body) {
		clearMessages(result)
		return nil
	}
	return result
}

func clearMessages(values [][]byte) {
	for _, value := range values {
		clear(value)
	}
}

func containsPong(body []byte, pingID uint64) bool {
	if len(body) == 20 && binary.LittleEndian.Uint32(body[:4]) == constructorPong {
		return binary.LittleEndian.Uint64(body[12:20]) == pingID
	}
	if len(body) < 8 || binary.LittleEndian.Uint32(body[:4]) != constructorMessageContainer {
		return false
	}
	count := int(binary.LittleEndian.Uint32(body[4:8]))
	if count < 0 || count > 64 {
		return false
	}
	offset := 8
	for index := 0; index < count; index++ {
		if len(body)-offset < 16 {
			return false
		}
		length := int(binary.LittleEndian.Uint32(body[offset+12 : offset+16]))
		if length < 4 || length&3 != 0 || len(body)-offset-16 < length {
			return false
		}
		if containsPong(body[offset+16:offset+16+length], pingID) {
			return true
		}
		offset += 16 + length
	}
	return false
}
