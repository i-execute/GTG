package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRawRoundTripAndPortable(t *testing.T) {
	credential, err := NewRawCredential(pattern(32, 1))
	if err != nil {
		t.Fatal(err)
	}
	vault := New()
	defer vault.Destroy()
	if err := vault.Put("auth-key", pattern(256, 2)); err != nil {
		t.Fatal(err)
	}
	if err := vault.Put("session", pattern(64, 3)); err != nil {
		t.Fatal(err)
	}
	encoded, err := vault.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	if bytes.Contains(encoded, pattern(64, 3)) {
		t.Fatal("plaintext in encoded vault")
	}
	opened, err := Open(encoded, credential)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Destroy()
	secret, err := opened.Get("auth-key")
	if err != nil {
		t.Fatal(err)
	}
	data, err := secret.Bytes()
	secret.Destroy()
	if err != nil || !bytes.Equal(data, pattern(256, 2)) {
		t.Fatal("round trip")
	}
	clear(data)
	portable := EncodePortable(encoded)
	decoded, err := DecodePortable(portable)
	if err != nil || !bytes.Equal(decoded, encoded) {
		t.Fatal("portable encoding")
	}
	clear(decoded)
}

func TestPassphraseKDFModes(t *testing.T) {
	for _, parameters := range []KDFParameters{
		{Algorithm: Argon2id, Time: 1, MemoryKiB: 8 * 1024, Threads: 1},
		{Algorithm: PBKDF2SHA256, Iterations: 100000},
	} {
		credential, err := NewPassphraseCredential([]byte("correct horse battery staple"), parameters)
		if err != nil {
			t.Fatal(err)
		}
		vault := New()
		if err := vault.Put("token", pattern(32, byte(parameters.Algorithm))); err != nil {
			t.Fatal(err)
		}
		encoded, err := vault.Marshal(credential)
		vault.Destroy()
		if err != nil {
			t.Fatal(err)
		}
		opened, err := Open(encoded, credential)
		clear(encoded)
		if err != nil {
			t.Fatal(err)
		}
		opened.Destroy()
	}
}

func TestVaultTamperUniformAuthentication(t *testing.T) {
	credential, err := NewRawCredential(pattern(32, 4))
	if err != nil {
		t.Fatal(err)
	}
	vault := New()
	if err := vault.Put("secret", pattern(32, 5)); err != nil {
		t.Fatal(err)
	}
	encoded, err := vault.Marshal(credential)
	vault.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	for i := range encoded {
		altered := append([]byte(nil), encoded...)
		altered[i] ^= 1
		opened, err := Open(altered, credential)
		if opened != nil || !errors.Is(err, ErrAuthentication) {
			t.Fatalf("tamper at %d: %v", i, err)
		}
		clear(altered)
	}
	wrong, err := NewRawCredential(pattern(32, 6))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(encoded, wrong); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
}

func TestRotateAndFile(t *testing.T) {
	oldCredential, err := NewRawCredential(pattern(32, 7))
	if err != nil {
		t.Fatal(err)
	}
	newCredential, err := NewMachineCredential(pattern(32, 8))
	if err != nil {
		t.Fatal(err)
	}
	vault := New()
	if err := vault.Put("session", pattern(48, 9)); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "nested", "session.vault")
	if err := SaveFile(path, vault, oldCredential); err != nil {
		t.Fatal(err)
	}
	vault.Destroy()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("vault permissions")
	}
	if err := RotateFile(path, oldCredential, newCredential); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path, oldCredential); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
	opened, err := LoadFile(path, newCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Destroy()
	secret, err := opened.Get("session")
	if err != nil {
		t.Fatal(err)
	}
	data, err := secret.Bytes()
	secret.Destroy()
	if err != nil || !bytes.Equal(data, pattern(48, 9)) {
		t.Fatal("rotated content")
	}
	clear(data)
}

func TestPayloadMigration(t *testing.T) {
	value := make([]byte, 2+len("old")+4)
	value[0] = 3
	copy(value[2:], "old")
	copy(value[5:], []byte{1, 2, 3, 4})
	payload := appendTLV(nil, 1, []byte{0})
	payload = appendTLV(payload, 17, value)
	entries, err := parsePayload(payload)
	clear(payload)
	clear(value)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyEntries(entries)
	data, err := entries["old"].Bytes()
	if err != nil || !bytes.Equal(data, []byte{1, 2, 3, 4}) {
		t.Fatal("migration")
	}
	clear(data)
}

func TestSecretDestroyAndConcurrentVault(t *testing.T) {
	secret, err := NewSecret(pattern(32, 10))
	if err != nil {
		t.Fatal(err)
	}
	_ = secret.LockMemory()
	secret.Destroy()
	if _, err := secret.Bytes(); !errors.Is(err, ErrDestroyed) {
		t.Fatal(err)
	}
	vault := New()
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func(worker byte) {
			defer group.Done()
			for i := 0; i < 100; i++ {
				_ = vault.Put("key", pattern(32, worker+byte(i)))
				secret, err := vault.Get("key")
				if err == nil {
					secret.Destroy()
				}
			}
		}(byte(worker))
	}
	group.Wait()
	vault.Destroy()
}

func pattern(length int, seed byte) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = seed + byte(i*17)
	}
	return out
}
