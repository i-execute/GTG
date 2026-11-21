package core

import (
	"bytes"
	"testing"
)

func TestOfflineTwoSidedChain(t *testing.T) {
	key := makePattern(256, 81)
	client, err := NewMTProto(key)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Destroy()
	server, err := NewMTProto(key)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Destroy()
	outbound := make([]byte, 24+333, 24+333+1024)
	originalOutbound := makePattern(333, 82)
	copy(outbound[24:], originalOutbound)
	sealedOutbound, err := client.SealInPlace(outbound, ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	inbound := make([]byte, 24+127, 24+127+1024)
	originalInbound := makePattern(127, 83)
	copy(inbound[24:], originalInbound)
	sealedInbound, err := server.SealInPlace(inbound, ServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	openedInbound, err := client.OpenInPlace(sealedInbound, ServerToClient)
	if err != nil || !bytes.Equal(openedInbound[:len(originalInbound)], originalInbound) {
		t.Fatal("server to client chain")
	}
	secret := makePattern(16, 84)
	init, clientTransport, err := NewObfuscatedInit(2, [4]byte{0xee, 0xee, 0xee, 0xee}, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clientTransport.Destroy()
	serverTransport, err := NewObfuscationFromInit(init, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer serverTransport.Destroy()
	wire := make([]byte, len(sealedOutbound))
	back := make([]byte, len(sealedOutbound))
	if err := clientTransport.Encrypt(wire, sealedOutbound); err != nil {
		t.Fatal(err)
	}
	if err := serverTransport.Decrypt(back, wire); err != nil || !bytes.Equal(back, sealedOutbound) {
		t.Fatal("obfuscated chain")
	}
	openedOutbound, err := server.OpenInPlace(back, ClientToServer)
	if err != nil || !bytes.Equal(openedOutbound[:len(originalOutbound)], originalOutbound) {
		t.Fatal("client to server chain")
	}
}
