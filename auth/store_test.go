package auth

import (
	"bytes"
	"testing"

	"github.com/i-execute/GTG/session"
	"github.com/i-execute/GTG/vault"
)

func TestVaultBackedAuthorizationMaterial(t *testing.T) {
	target := vault.New()
	token := []byte("token-value")
	if err := StoreBotToken(target, "main", token); err != nil {
		t.Fatal(err)
	}
	secret, err := LoadBotToken(target, "main")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := secret.Bytes()
	secret.Destroy()
	if err != nil || !bytes.Equal(loaded, token) {
		t.Fatal(err)
	}
	clear(loaded)
	key := make([]byte, 256)
	key[0] = 7
	user := session.Telethon{DCID: 1, Address: "149.154.175.10", Port: 443, AuthKey: key}
	if err := StoreUserSession(target, "main", user); err != nil {
		t.Fatal(err)
	}
	decoded, err := LoadUserSession(target, "main")
	if err != nil || decoded.DCID != user.DCID || !bytes.Equal(decoded.AuthKey, user.AuthKey) {
		t.Fatal(err)
	}
	user.Destroy()
	decoded.Destroy()
	target.Destroy()
}
