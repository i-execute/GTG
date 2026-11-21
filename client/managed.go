package client

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/i-execute/GTG/tl"
)

var ErrLifecycle = errors.New("gtg: client lifecycle failed")

type RPCSession interface {
	Call(context.Context, tl.Dynamic) (tl.Dynamic, error)
	Ping(uint64) error
	Close() error
}

type SessionDialer func(context.Context, Config) (RPCSession, error)
type DCResolver func(context.Context, Config, int) (Config, error)

type RetryPolicy struct {
	MaxAttempts  int
	Backoff      time.Duration
	MaxFloodWait time.Duration
}

type Managed struct {
	mu      sync.Mutex
	config  Config
	dial    SessionDialer
	resolve DCResolver
	policy  RetryPolicy
	session RPCSession
	closed  bool
}

func NewManaged(config Config, dialer SessionDialer, resolver DCResolver, policy RetryPolicy) (*Managed, error) {
	if config.Endpoint == "" || len(config.AuthKey) != 256 || dialer == nil {
		return nil, ErrLifecycle
	}
	if policy.MaxAttempts < 1 {
		policy.MaxAttempts = 1
	}
	if policy.Backoff < 0 || policy.MaxFloodWait < 0 {
		return nil, ErrLifecycle
	}
	return &Managed{config: cloneConfig(config), dial: dialer, resolve: resolver, policy: policy}, nil
}

func DialManaged(config Config, resolver DCResolver, policy RetryPolicy) (*Managed, error) {
	return NewManaged(config, func(ctx context.Context, config Config) (RPCSession, error) {
		return Dial(ctx, config)
	}, resolver, policy)
}

func (x *Managed) Call(ctx context.Context, request tl.Dynamic) (tl.Dynamic, error) {
	if x == nil {
		return tl.Dynamic{}, ErrLifecycle
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return tl.Dynamic{}, ErrLifecycle
	}
	var last error
	for attempt := 0; attempt < x.policy.MaxAttempts; attempt++ {
		session, err := x.ensure(ctx)
		if err == nil {
			value, callErr := session.Call(ctx, request)
			if callErr == nil {
				return value, nil
			}
			err = callErr
		}
		last = err
		var rpc *RPCError
		if errors.As(err, &rpc) {
			if rpc.MigrateDC > 0 && x.resolve != nil {
				if err := x.migrate(ctx, rpc.MigrateDC); err != nil {
					return tl.Dynamic{}, err
				}
				continue
			}
			if rpc.FloodWait > 0 {
				wait := time.Duration(rpc.FloodWait) * time.Second
				if x.policy.MaxFloodWait == 0 || wait > x.policy.MaxFloodWait {
					return tl.Dynamic{}, err
				}
				if waitContext(ctx, wait) != nil {
					return tl.Dynamic{}, ctx.Err()
				}
				continue
			}
			return tl.Dynamic{}, err
		}
		x.drop()
		if attempt+1 < x.policy.MaxAttempts && x.policy.Backoff != 0 {
			if waitContext(ctx, x.policy.Backoff) != nil {
				return tl.Dynamic{}, ctx.Err()
			}
		}
	}
	if last == nil {
		last = ErrLifecycle
	}
	return tl.Dynamic{}, last
}

func (x *Managed) Ping(ctx context.Context, id uint64) error {
	if x == nil {
		return ErrLifecycle
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return ErrLifecycle
	}
	session, err := x.ensure(ctx)
	if err != nil {
		return err
	}
	if err := session.Ping(id); err != nil {
		x.drop()
		return err
	}
	return nil
}

func (x *Managed) Close() error {
	if x == nil {
		return nil
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return nil
	}
	x.closed = true
	err := x.closeSession()
	clear(x.config.AuthKey)
	clear(x.config.APIHash)
	return err
}

func (x *Managed) ensure(ctx context.Context) (RPCSession, error) {
	if x.session != nil {
		return x.session, nil
	}
	config := cloneConfig(x.config)
	defer clear(config.AuthKey)
	defer clear(config.APIHash)
	session, err := x.dial(ctx, config)
	if err != nil {
		return nil, err
	}
	x.session = session
	return session, nil
}

func (x *Managed) migrate(ctx context.Context, dc int) error {
	current := cloneConfig(x.config)
	next, err := x.resolve(ctx, current, dc)
	clear(current.AuthKey)
	clear(current.APIHash)
	if err != nil {
		return err
	}
	if next.Endpoint == "" || len(next.AuthKey) != 256 {
		return ErrLifecycle
	}
	replacement := cloneConfig(next)
	x.drop()
	clear(x.config.AuthKey)
	clear(x.config.APIHash)
	x.config = replacement
	return nil
}

func (x *Managed) drop() {
	_ = x.closeSession()
}

func (x *Managed) closeSession() error {
	if x.session == nil {
		return nil
	}
	err := x.session.Close()
	x.session = nil
	return err
}

func waitContext(ctx context.Context, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func cloneConfig(value Config) Config {
	result := value
	result.AuthKey = append([]byte(nil), value.AuthKey...)
	result.APIHash = append([]byte(nil), value.APIHash...)
	return result
}
