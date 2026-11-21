//go:build integration

package client

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/i-execute/GTG/internal/bootstrap"
	"github.com/i-execute/GTG/session"
)

func TestLiveUserGetMe(t *testing.T) {
	if os.Getenv("GTG_LIVE") != "1" {
		t.Skip("set GTG_LIVE=1 with GTG_STRING_SESSION, GTG_API_ID, and GTG_API_HASH")
	}
	text, okText := os.LookupEnv("GTG_STRING_SESSION")
	apiIDText, okID := os.LookupEnv("GTG_API_ID")
	apiHash, okHash := os.LookupEnv("GTG_API_HASH")
	if !okText || !okID || !okHash || text == "" || apiIDText == "" || apiHash == "" {
		t.Skip("set GTG_STRING_SESSION, GTG_API_ID, and GTG_API_HASH for the restricted self getMe test")
	}
	apiID, err := strconv.Atoi(apiIDText)
	if err != nil || apiID <= 0 {
		t.Fatal("GTG_API_ID is invalid")
	}
	stored, err := session.ParseTelethon(text)
	if err != nil {
		t.Fatal("GTG_STRING_SESSION is invalid")
	}
	defer stored.Destroy()
	hash := []byte(apiHash)
	defer clear(hash)
	endpoint := net.JoinHostPort(stored.Address, strconv.Itoa(int(stored.Port)))
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	client, err := Dial(ctx, Config{Endpoint: endpoint, Transport: Intermediate, AuthKey: stored.AuthKey, APIID: apiID, APIHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.GetMe(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestLiveBotGetMe(t *testing.T) {
	if os.Getenv("GTG_LIVE") != "1" {
		t.Skip("set GTG_LIVE=1 with GTG_BOT_TOKEN, GTG_API_ID, GTG_API_HASH, and GTG_BOT_TOKEN_ROTATED=1")
	}
	token, okToken := os.LookupEnv("GTG_BOT_TOKEN")
	apiIDText, okID := os.LookupEnv("GTG_API_ID")
	apiHash, okHash := os.LookupEnv("GTG_API_HASH")
	if !okToken || !okID || !okHash || token == "" || apiIDText == "" || apiHash == "" {
		t.Skip("set GTG_BOT_TOKEN, GTG_API_ID, and GTG_API_HASH for the restricted bot getMe test")
	}
	if os.Getenv("GTG_BOT_TOKEN_ROTATED") != "1" {
		t.Skip("rotate the previously exposed bot token, then set GTG_BOT_TOKEN_ROTATED=1")
	}
	apiID, err := strconv.Atoi(apiIDText)
	if err != nil || apiID <= 0 {
		t.Fatal("GTG_API_ID is invalid")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	result, err := bootstrap.CreateAuthKey(ctx, "149.154.175.50:443", bootstrap.Intermediate, false)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(result.AuthKey)
	defer result.Close()
	hash := []byte(apiHash)
	defer clear(hash)
	client, err := Dial(ctx, Config{Endpoint: result.Endpoint, Transport: Intermediate, AuthKey: result.AuthKey, ServerSalt: result.ServerSalt, TimeOffset: result.TimeOffset, APIID: apiID, APIHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	secret := []byte(token)
	defer clear(secret)
	if _, err := client.AuthorizeBot(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetMe(ctx); err != nil {
		t.Fatal(err)
	}
}
