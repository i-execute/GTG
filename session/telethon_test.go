package session

import (
	"bytes"
	"testing"

	"github.com/i-execute/GTG/vault"
)

func TestTelethonRoundTripAndVault(t *testing.T) {
	key := make([]byte, 256)
	for index := range key {
		key[index] = byte(index + 1)
	}
	original := Telethon{DCID: 2, Address: "149.154.167.40", Port: 443, AuthKey: key}
	text, err := original.String()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTelethon(text)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.DCID != original.DCID || parsed.Address != original.Address || parsed.Port != original.Port || !bytes.Equal(parsed.AuthKey, original.AuthKey) {
		t.Fatal("parse mismatch")
	}
	target := vault.New()
	if err := StoreTelethon(target, "primary", parsed); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTelethon(target, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DCID != original.DCID || loaded.Address != original.Address || loaded.Port != original.Port || !bytes.Equal(loaded.AuthKey, original.AuthKey) {
		t.Fatal("vault mismatch")
	}
	original.Destroy()
	parsed.Destroy()
	loaded.Destroy()
	target.Destroy()
}

func TestTelethonRejectsMalformed(t *testing.T) {
	for _, value := range []string{"", "0abc", "1", "1!!!!"} {
		if _, err := ParseTelethon(value); err == nil {
			t.Fatal(value)
		}
	}
}
