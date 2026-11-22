package client

import (
	"testing"

	"github.com/i-execute/GTG/session"
)

func TestConfigFromAccount(t *testing.T) {
	account := session.Account{Kind: session.BotAccount, DCID: 2, DCs: []session.DC{{ID: 2, Address: "149.154.167.50", Port: 443}}, AuthKey: make([]byte, 256), APIID: 1}
	config, err := ConfigFromAccount(account, 123, []byte("hash"))
	if err != nil {
		t.Fatal(err)
	}
	if config.Endpoint != "149.154.167.50:443" || config.APIID != 123 || len(config.AuthKey) != 256 || string(config.APIHash) != "hash" {
		t.Fatal("config mismatch")
	}
	clear(account.AuthKey)
	clear(config.AuthKey)
	clear(config.APIHash)
}
