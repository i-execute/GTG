//go:build integration

package core

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestIntegrationTestDCReqPQ(t *testing.T) {
	if os.Getenv("GTG_TELEGRAM_INTEGRATION") != "1" {
		t.Skip("set GTG_TELEGRAM_INTEGRATION=1 to enable the public test-DC probe")
	}
	target := os.Getenv("GTG_TELEGRAM_TEST_DC")
	if target == "" {
		target = "test-api.telegram.org:443"
	}
	connection, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		t.Skipf("test DC unavailable: %v", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 20)
	binary.LittleEndian.PutUint32(body[:4], 0xbe7e8ef1)
	copy(body[4:], nonce[:])
	packet := make([]byte, 20+len(body))
	messageID := uint64(time.Now().Unix())<<32 | uint64(time.Now().Nanosecond())<<32/1_000_000_000
	binary.LittleEndian.PutUint64(packet[8:16], messageID&^3)
	binary.LittleEndian.PutUint32(packet[16:20], uint32(len(body)))
	copy(packet[20:], body)
	var start [4]byte
	binary.LittleEndian.PutUint32(start[:], 0xeeeeeeee)
	if _, err := connection.Write(start[:]); err != nil {
		t.Skipf("test DC transport unavailable: %v", err)
	}
	var length [4]byte
	binary.LittleEndian.PutUint32(length[:], uint32(len(packet)))
	if _, err := connection.Write(length[:]); err != nil {
		t.Skipf("test DC transport unavailable: %v", err)
	}
	if _, err := connection.Write(packet); err != nil {
		t.Skipf("test DC transport unavailable: %v", err)
	}
	if _, err := io.ReadFull(connection, length[:]); err != nil {
		t.Skipf("test DC transport unavailable: %v", err)
	}
	responseLength := int(binary.LittleEndian.Uint32(length[:]))
	if responseLength < 40 || responseLength > 1<<20 {
		t.Fatalf("invalid response size %d", responseLength)
	}
	response := make([]byte, responseLength)
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Skipf("test DC transport unavailable: %v", err)
	}
	if !bytes.Equal(response[:8], make([]byte, 8)) || int(binary.LittleEndian.Uint32(response[16:20])) != len(response)-20 {
		t.Fatal("invalid unencrypted MTProto response")
	}
	result := response[20:]
	if len(result) < 36 || binary.LittleEndian.Uint32(result[:4]) != 0x05162463 || !bytes.Equal(result[4:20], nonce[:]) {
		t.Fatalf("unexpected constructor or nonce: %x", result[:minInt(len(result), 20)])
	}
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
