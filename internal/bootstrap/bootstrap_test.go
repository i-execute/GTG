package bootstrap

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/i-execute/GTG/core"
)

func TestKnownServerKeysHaveStableTLFingerprint(t *testing.T) {
	for _, item := range []struct {
		test        bool
		fingerprint uint64
	}{
		{test: false, fingerprint: 0xd09d1d85de64fd85},
		{test: true, fingerprint: 0xb25898df208d2603},
	} {
		keys, err := KnownServerKeys(item.test)
		if err != nil || len(keys) != 1 {
			t.Fatal(err)
		}
		fingerprint, err := core.RSAFingerprint(keys[0])
		if err != nil || fingerprint != item.fingerprint {
			t.Fatal(err)
		}
		selected, selectedFingerprint, ok := chooseKey(keys, []uint64{fingerprint})
		if !ok || selectedFingerprint != fingerprint || !bytes.Equal(selected.Modulus, keys[0].Modulus) {
			t.Fatal("key selection failed")
		}
	}
}

func TestPlainRoundTripWithTransportPadding(t *testing.T) {
	body := encodeReqPQ([16]byte{1})
	packet := encodePlain(12, body)
	packet = append(packet, 1, 2, 3)
	messageID, decoded, err := decodePlain(packet)
	if err != nil || messageID != 12 || !bytes.Equal(decoded, body) {
		t.Fatal(err)
	}
}

func TestTransportOpeningsAndFrames(t *testing.T) {
	for _, transport := range []Transport{Abridged, Intermediate, PaddedIntermediate} {
		client, server := net.Pipe()
		connection := &Connection{connection: client, transport: transport}
		completed := make(chan error, 1)
		go func() {
			defer server.Close()
			switch transport {
			case Abridged:
				var opening [1]byte
				if _, err := io.ReadFull(server, opening[:]); err != nil || opening[0] != 0xef {
					completed <- ErrTransport
					return
				}
				var length [1]byte
				if _, err := io.ReadFull(server, length[:]); err != nil || length[0] != 2 {
					completed <- ErrTransport
					return
				}
			case Intermediate, PaddedIntermediate:
				var opening [4]byte
				if _, err := io.ReadFull(server, opening[:]); err != nil {
					completed <- err
					return
				}
				expected := uint32(0xeeeeeeee)
				if transport == PaddedIntermediate {
					expected = 0xdddddddd
				}
				if binary.LittleEndian.Uint32(opening[:]) != expected {
					completed <- ErrTransport
					return
				}
				var length [4]byte
				if _, err := io.ReadFull(server, length[:]); err != nil || binary.LittleEndian.Uint32(length[:]) < 8 {
					completed <- ErrTransport
					return
				}
				body := make([]byte, binary.LittleEndian.Uint32(length[:]))
				if _, err := io.ReadFull(server, body); err != nil {
					completed <- err
					return
				}
				if !bytes.Equal(body[:8], make([]byte, 8)) {
					completed <- ErrTransport
					return
				}
				completed <- nil
				return
			}
			body := make([]byte, 8)
			_, err := io.ReadFull(server, body)
			completed <- err
		}()
		if err := connection.writeOpening(); err != nil {
			t.Fatal(err)
		}
		if err := connection.WritePacket(make([]byte, 8)); err != nil {
			t.Fatal(err)
		}
		if err := <-completed; err != nil {
			t.Fatal(err)
		}
		client.Close()
	}
}

func TestDecryptServerDH(t *testing.T) {
	var nonce [16]byte
	var serverNonce [16]byte
	for index := range nonce {
		nonce[index] = byte(index + 1)
		serverNonce[index] = byte(index + 17)
	}
	var newNonce [32]byte
	for index := range newNonce {
		newNonce[index] = byte(index + 33)
	}
	material, err := core.DeriveHandshakeTemporaryAES(newNonce[:], serverNonce[:])
	if err != nil {
		t.Fatal(err)
	}
	prime := make([]byte, 256)
	public := make([]byte, 256)
	prime[0] = 1
	public[0] = 2
	inner := encoder{}
	inner.u32(constructorServerDHInner)
	inner.fixed(nonce[:])
	inner.fixed(serverNonce[:])
	inner.i32(3)
	inner.bytes(prime)
	inner.bytes(public)
	inner.i32(123)
	hash := sha1.Sum(inner.data)
	plain := append(hash[:], inner.data...)
	for len(plain)&15 != 0 {
		plain = append(plain, 0)
	}
	ige, err := core.NewIGE(material.Key[:])
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(plain))
	if err := ige.Encrypt(ciphertext, plain, material.IV[:]); err != nil {
		t.Fatal(err)
	}
	ige.Destroy()
	decoded, err := decryptServerDH(ciphertext, material)
	if err != nil || decoded.generator != 3 || decoded.serverTime != 123 || !bytes.Equal(decoded.prime, prime) || !bytes.Equal(decoded.public, public) {
		t.Fatal(err)
	}
	clear(ciphertext)
	clear(plain)
	clear(inner.data)
	clear(prime)
	clear(public)
	clear(decoded.prime)
	clear(decoded.public)
}

func TestLegacyPacketRoundTripAndPongContainer(t *testing.T) {
	auth := make([]byte, 256)
	for index := range auth {
		auth[index] = byte(index + 19)
	}
	box, err := newLegacyMTProto(auth)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 48)
	binary.LittleEndian.PutUint32(payload[28:32], 16)
	binary.LittleEndian.PutUint32(payload[32:36], constructorPingDelayDisconnect)
	binary.LittleEndian.PutUint64(payload[36:44], 77)
	binary.LittleEndian.PutUint32(payload[44:48], 30)
	sealed, err := box.seal(payload, true)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := box.open(sealed, false)
	if err != nil || !bytes.Equal(opened[:48], payload) {
		t.Fatal(err)
	}
	container := make([]byte, 8+16+20)
	binary.LittleEndian.PutUint32(container[:4], constructorMessageContainer)
	binary.LittleEndian.PutUint32(container[4:8], 1)
	binary.LittleEndian.PutUint32(container[20:24], 20)
	binary.LittleEndian.PutUint32(container[24:28], constructorPong)
	binary.LittleEndian.PutUint64(container[36:44], 77)
	if !containsPong(container, 77) || containsPong(container, 78) {
		t.Fatalf("pong container parsing failed body=%x first=%t second=%t", container, containsPong(container, 77), containsPong(container, 78))
	}
	messages := unpackMessages(container)
	if len(messages) != 1 || !bytes.Equal(messages[0], container[24:44]) {
		t.Fatal("message container unpacking failed")
	}
	clearMessages(messages)
	clear(auth)
	clear(payload)
	clear(sealed)
	clear(opened)
	clear(container)
	box.destroy()
}

func TestRPCResultDetection(t *testing.T) {
	message := make([]byte, 12)
	binary.LittleEndian.PutUint32(message[:4], constructorRPCResult)
	binary.LittleEndian.PutUint64(message[4:12], 99)
	if !containsRPCResult([][]byte{[]byte{1, 2, 3}, message}, 99) {
		t.Fatal("expected rpc result")
	}
	if containsRPCResult([][]byte{message}, 100) {
		t.Fatal("accepted wrong request id")
	}
}

func TestMessageIDsMonotonic(t *testing.T) {
	ids := messageIDs{}
	now := time.Unix(100, 1)
	first := ids.next(now)
	second := ids.next(now)
	if first&3 != 0 || second&3 != 0 || second <= first {
		t.Fatal("message IDs are not monotonic")
	}
}
