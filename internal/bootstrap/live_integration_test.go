//go:build integration

package bootstrap

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestLiveBootstrapAuthorization(t *testing.T) {
	if os.Getenv("GTG_LIVE") != "1" {
		t.Skip("set GTG_LIVE=1 to enable live MTProto bootstrap authorization")
	}
	endpoints := []struct {
		address string
		test    bool
	}{
		{address: "149.154.175.50:443", test: false},
		{address: "149.154.175.50:80", test: false},
		{address: "149.154.175.50:5222", test: false},
		{address: "149.154.175.10:443", test: true},
		{address: "149.154.175.10:80", test: true},
		{address: "149.154.175.10:5222", test: true},
	}
	transports := []Transport{Intermediate, Abridged, PaddedIntermediate}
	succeeded := 0
	reached := 0
	for _, endpoint := range endpoints {
		for _, transport := range transports {
			ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			result, err := CreateAuthKey(ctx, endpoint.address, transport, endpoint.test)
			cancel()
			if err != nil {
				resultText := liveFailure(err)
				if resultText != "network-unavailable" {
					reached++
				}
				t.Logf("live bootstrap endpoint=%s test=%t transport=%d result=%s", endpoint.address, endpoint.test, transport, resultText)
				continue
			}
			reached++
			if len(result.AuthKey) != 256 || result.Endpoint != endpoint.address || result.IsTestServer != endpoint.test {
				clear(result.AuthKey)
				t.Fatal("live bootstrap returned invalid result")
			}
			session, err := DialEncrypted(context.Background(), result)
			if err == nil {
				err = session.Ping(uint64(time.Now().UnixNano()))
				_ = session.Close()
			}
			clear(result.AuthKey)
			if err != nil {
				t.Logf("live bootstrap endpoint=%s test=%t transport=%d result=encrypted-ping-failed", endpoint.address, endpoint.test, transport)
				continue
			}
			t.Logf("live bootstrap endpoint=%s test=%t transport=%d result=authenticated-and-encrypted-ping-pong", endpoint.address, endpoint.test, transport)
			succeeded++
			break
		}
	}
	if succeeded == 0 && reached == 0 {
		t.Skip("Telegram endpoints unavailable; rerun when public network access is available")
	}
	if succeeded == 0 {
		t.Fatal("no reachable Telegram endpoint completed bootstrap authorization")
	}
}

func liveFailure(err error) string {
	var failure authFailureError
	if errors.As(err, &failure) {
		return failure.stage
	}
	if errors.Is(err, ErrAuth) {
		return "protocol-rejected"
	}
	if errors.Is(err, ErrTransport) {
		return "transport-rejected"
	}
	return "network-unavailable"
}
