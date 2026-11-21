package core

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"testing"
)

func TestSecretChatDerivation(t *testing.T) {
	key := makePattern(256, 251)
	plain := makePattern(64, 252)
	messageKey, err := SecretChatMessageKey(key, plain, SecretChatFromOriginator)
	if err != nil {
		t.Fatal(err)
	}
	full := sha256.Sum256(append(key[88:120:120], plain...))
	if !bytes.Equal(messageKey[:], full[8:24]) {
		t.Fatal("message key formula")
	}
	aesKey, aesIV, err := DeriveSecretChatAES(key, messageKey[:], SecretChatToOriginator)
	if err != nil {
		t.Fatal(err)
	}
	a := sha256.Sum256(append(messageKey[:], key[8:44:44]...))
	b := sha256.Sum256(append(key[48:84:84], messageKey[:]...))
	var wantKey [32]byte
	var wantIV [32]byte
	copy(wantKey[:8], a[:8])
	copy(wantKey[8:24], b[8:24])
	copy(wantKey[24:], a[24:])
	copy(wantIV[:8], b[:8])
	copy(wantIV[8:24], a[8:24])
	copy(wantIV[24:], b[24:])
	if aesKey != wantKey || aesIV != wantIV {
		t.Fatal("AES derivation formula")
	}
}

func TestSecretChatSealOpen(t *testing.T) {
	key := makePattern(256, 253)
	chat, err := NewSecretChat(key)
	if err != nil {
		t.Fatal(err)
	}
	defer chat.Destroy()
	plain := makePattern(64, 254)
	messageKey, sealed, err := chat.Seal(make([]byte, 0, len(plain)), plain, SecretChatFromOriginator)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := chat.Open(make([]byte, 0, len(plain)), messageKey[:], sealed, SecretChatFromOriginator)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatal("round trip")
	}
	packet := make([]byte, 24+71, 24+71+1024)
	copy(packet[24:], makePattern(71, 255))
	wantPacket := append([]byte(nil), packet[24:]...)
	sealedPacket, err := chat.SealInPlace(packet, SecretChatToOriginator)
	if err != nil {
		t.Fatal(err)
	}
	openedPacket, err := chat.OpenInPlace(sealedPacket, SecretChatToOriginator)
	if err != nil || len(openedPacket) < 83 || !bytes.Equal(openedPacket[:71], wantPacket) {
		t.Fatal("in place round trip")
	}
	sealedPacket[0] ^= 1
	if _, err := chat.OpenInPlace(sealedPacket, SecretChatToOriginator); err == nil {
		t.Fatal("accepted altered fingerprint")
	}
}

func TestSecretChatFingerprintAndVisualization(t *testing.T) {
	initial := makePattern(256, 1)
	active := makePattern(256, 2)
	fingerprint, err := SecretChatKeyFingerprint(initial)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha1.Sum(initial)
	if !bytes.Equal(fingerprint[:], digest[12:]) {
		t.Fatal("fingerprint")
	}
	visual, err := SecretChatVisualization(initial, active)
	if err != nil {
		t.Fatal(err)
	}
	first := sha1.Sum(initial)
	second := sha256.Sum256(active)
	if !bytes.Equal(visual[:16], first[:16]) || !bytes.Equal(visual[16:], second[:20]) {
		t.Fatal("visualization")
	}
}
