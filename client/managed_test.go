package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/i-execute/GTG/tl"
)

type fakeSession struct {
	call   func(context.Context, tl.Dynamic) (tl.Dynamic, error)
	closed int
}

func (x *fakeSession) Call(ctx context.Context, value tl.Dynamic) (tl.Dynamic, error) {
	return x.call(ctx, value)
}

func (x *fakeSession) Ping(uint64) error {
	return nil
}

func (x *fakeSession) Close() error {
	x.closed++
	return nil
}

func managedConfig() Config {
	return Config{Endpoint: "first", AuthKey: make([]byte, 256)}
}

func TestManagedReconnectsAfterTransportFailure(t *testing.T) {
	var calls int
	first := &fakeSession{call: func(context.Context, tl.Dynamic) (tl.Dynamic, error) {
		return tl.Dynamic{}, errors.New("transport")
	}}
	second := &fakeSession{call: func(context.Context, tl.Dynamic) (tl.Dynamic, error) {
		return tl.Dynamic{Name: "ok", Fields: map[string]any{}}, nil
	}}
	managed, err := NewManaged(managedConfig(), func(context.Context, Config) (RPCSession, error) {
		calls++
		if calls == 1 {
			return first, nil
		}
		return second, nil
	}, nil, RetryPolicy{MaxAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	value, err := managed.Call(context.Background(), tl.Dynamic{Name: "request", Fields: map[string]any{}})
	if err != nil || value.Name != "ok" || first.closed != 1 || calls != 2 {
		t.Fatal("reconnect mismatch")
	}
}

func TestManagedMigratesAndWaitsWithinPolicy(t *testing.T) {
	var endpoints []string
	first := &fakeSession{call: func(context.Context, tl.Dynamic) (tl.Dynamic, error) {
		return tl.Dynamic{}, &RPCError{Code: 303, MigrateDC: 2}
	}}
	second := &fakeSession{call: func(context.Context, tl.Dynamic) (tl.Dynamic, error) {
		return tl.Dynamic{Name: "migrated", Fields: map[string]any{}}, nil
	}}
	managed, err := NewManaged(managedConfig(), func(ctx context.Context, config Config) (RPCSession, error) {
		endpoints = append(endpoints, config.Endpoint)
		if len(endpoints) == 1 {
			return first, nil
		}
		return second, nil
	}, func(ctx context.Context, current Config, dc int) (Config, error) {
		if dc != 2 || current.Endpoint != "first" {
			t.Fatal("unexpected migration input")
		}
		next := managedConfig()
		next.Endpoint = "second"
		return next, nil
	}, RetryPolicy{MaxAttempts: 2, MaxFloodWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	value, err := managed.Call(context.Background(), tl.Dynamic{Name: "request", Fields: map[string]any{}})
	if err != nil || value.Name != "migrated" || len(endpoints) != 2 || endpoints[1] != "second" {
		t.Fatal("migration mismatch")
	}
}

func TestManagedDoesNotSleepPastPolicy(t *testing.T) {
	managed, err := NewManaged(managedConfig(), func(context.Context, Config) (RPCSession, error) {
		return &fakeSession{call: func(context.Context, tl.Dynamic) (tl.Dynamic, error) {
			return tl.Dynamic{}, &RPCError{Code: 420, FloodWait: 2}
		}}, nil
	}, nil, RetryPolicy{MaxAttempts: 2, MaxFloodWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = managed.Call(context.Background(), tl.Dynamic{Name: "request", Fields: map[string]any{}})
	var rpc *RPCError
	if !errors.As(err, &rpc) || rpc.FloodWait != 2 {
		t.Fatal("flood wait policy mismatch")
	}
}
