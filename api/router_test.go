package api

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/i-execute/GTG/tl"
)

func TestRouterMiddlewareOrder(t *testing.T) {
	router := NewRouter()
	var value atomic.Int32
	if err := router.Use(func(next Handler) Handler {
		return func(ctx context.Context, update tl.Dynamic) error {
			value.Add(1)
			return next(ctx, update)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := router.Handle("update", func(context.Context, tl.Dynamic) error {
		value.Add(10)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := router.Dispatch(t.Context(), tl.Dynamic{Name: "update"}); err != nil || value.Load() != 11 {
		t.Fatal(err)
	}
}
