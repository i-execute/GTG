package auth

import (
	"errors"
	"strings"

	"github.com/i-execute/GTG/session"
	"github.com/i-execute/GTG/vault"
)

var ErrStore = errors.New("gtg: invalid authorization store request")

func StoreBotToken(target *vault.Vault, name string, token []byte) error {
	if target == nil || !validName(name) || len(token) == 0 {
		return ErrStore
	}
	copyToken := append([]byte(nil), token...)
	err := target.Put("bot-token-"+name, copyToken)
	clear(copyToken)
	return err
}

func LoadBotToken(source *vault.Vault, name string) (*vault.Secret, error) {
	if source == nil || !validName(name) {
		return nil, ErrStore
	}
	return source.Get("bot-token-" + name)
}

func DeleteBotToken(target *vault.Vault, name string) error {
	if target == nil || !validName(name) {
		return ErrStore
	}
	return target.Delete("bot-token-" + name)
}

func StoreUserSession(target *vault.Vault, name string, value session.Telethon) error {
	if target == nil || !validName(name) {
		return ErrStore
	}
	return session.StoreTelethon(target, "user-"+name, value)
}

func LoadUserSession(source *vault.Vault, name string) (session.Telethon, error) {
	if source == nil || !validName(name) {
		return session.Telethon{}, ErrStore
	}
	return session.LoadTelethon(source, "user-"+name)
}

func validName(name string) bool {
	return name != "" && len(name) <= 128 && !strings.ContainsAny(name, "\x00/\\")
}
