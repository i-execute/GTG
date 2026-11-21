package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestObfuscation(t *testing.T) {
	secret := makePattern(16, 221)
	tag := [4]byte{0xef, 0xef, 0xef, 0xef}
	init, client, err := NewObfuscatedInit(2, tag, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Destroy()
	server, err := NewObfuscationFromInit(init, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Destroy()
	plain := makePattern(4097, 222)
	sealed := make([]byte, len(plain))
	opened := make([]byte, len(plain))
	if err := client.Encrypt(sealed, plain); err != nil {
		t.Fatal(err)
	}
	if err := server.Decrypt(opened, sealed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plain) {
		t.Fatal("client stream mismatch")
	}
	if err := server.Encrypt(sealed, plain); err != nil {
		t.Fatal(err)
	}
	if err := client.Decrypt(opened, sealed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plain) {
		t.Fatal("server stream mismatch")
	}
}

func TestObfuscationStreamPositions(t *testing.T) {
	secret := makePattern(16, 230)
	init, client, err := NewObfuscatedInit(2, [4]byte{0xee, 0xee, 0xee, 0xee}, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Destroy()
	payload := makePattern(71, 231)
	got := make([]byte, len(payload))
	if err := client.Encrypt(got, payload); err != nil {
		t.Fatal(err)
	}
	out := referenceObfuscationStream(init, secret, false)
	var discarded [64]byte
	out.XORKeyStream(discarded[:], discarded[:])
	want := make([]byte, len(payload))
	out.XORKeyStream(want, payload)
	if !bytes.Equal(got, want) {
		t.Fatal("client outbound CTR position")
	}
	server, err := NewObfuscationFromInit(init, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Destroy()
	if err := server.Encrypt(got, payload); err != nil {
		t.Fatal(err)
	}
	out = referenceObfuscationStream(init, secret, true)
	out.XORKeyStream(want, payload)
	if !bytes.Equal(got, want) {
		t.Fatal("server outbound CTR position")
	}
}

func TestObfuscationSecrets(t *testing.T) {
	for _, prefix := range []byte{0xdd, 0xee} {
		secret := append([]byte{prefix}, makePattern(16, prefix)...)
		if prefix == 0xee {
			secret = append(secret, []byte("example.com")...)
		}
		kind, material, err := ParseProxySecret(secret)
		if err != nil || len(material) != 16 || kind == ProxySecretPlain {
			t.Fatal("secret parse")
		}
		if prefix == 0xee {
			domain, err := FakeTLSDomain(secret)
			if err != nil || !bytes.Equal(domain, []byte("example.com")) {
				t.Fatal("fake TLS domain parse")
			}
		}
	}
}

func TestFakeTLSDigests(t *testing.T) {
	secret := mustHex(t, "ee0102030405060708090a0b0c0d0e0f106578616d706c652e636f6d")
	record := mustHex(t, "0724415e7b98b5d2ef0c294663809dbad7f4112e4b6885a2bfdcf91633506d8aa7c4e1fe1b3855728facc9e603203d5a7794b1ceeb0825425f7c99b6d3f00d2a4764819ebbd8f5122f4c6986a3c0ddfa1734516e8ba8c5e2ff1c39567390adcae704213e")
	wantClient := mustHex(t, "e516a6f68f53b534d5924b5561b13fc3d983c6dc44bbd6a3f0b8028913ae644d")
	gotClient, err := FakeTLSClientDigest(secret, record, 13, 0x65f12345)
	if err != nil || !bytes.Equal(gotClient[:], wantClient) {
		t.Fatal("client HMAC")
	}
	if err := VerifyFakeTLSClientDigest(secret, record, 13, 0x65f12345, gotClient[:]); err != nil {
		t.Fatal(err)
	}
	response := mustHex(t, "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9eafb")
	wantServer := mustHex(t, "d28e50479da75b578ab2b9c0b6851e6093f5d140a4393cccfef52ea61185906a")
	gotServer, err := FakeTLSServerDigest(secret, gotClient[:], response, 31)
	if err != nil || !bytes.Equal(gotServer[:], wantServer) {
		t.Fatal("server HMAC")
	}
	if err := VerifyFakeTLSServerDigest(secret, gotClient[:], response, 31, gotServer[:]); err != nil {
		t.Fatal(err)
	}
}

func TestObfuscationPrefix(t *testing.T) {
	init := make([]byte, 64)
	init[0] = 0xef
	if _, err := NewObfuscationFromInit(init, nil); err == nil {
		t.Fatal("accepted forbidden init")
	}
}

func referenceObfuscationStream(init, secret []byte, backwards bool) cipher.Stream {
	keyMaterial := append([]byte(nil), init[8:56]...)
	if backwards {
		for left, right := 0, len(keyMaterial)-1; left < right; left, right = left+1, right-1 {
			keyMaterial[left], keyMaterial[right] = keyMaterial[right], keyMaterial[left]
		}
	}
	keySum := sha256.Sum256(append(keyMaterial[:32:32], secret...))
	ivSum := sha256.Sum256(append(keyMaterial[32:48:48], secret...))
	block, err := aes.NewCipher(keySum[:])
	if err != nil {
		panic(err)
	}
	return cipher.NewCTR(block, ivSum[:16])
}

func mustHex(t *testing.T, text string) []byte {
	t.Helper()
	out, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
