package api

import (
	"context"
	"sync"

	"github.com/i-execute/GTG/tl"
)

type Handler func(context.Context, tl.Dynamic) error

type Middleware func(Handler) Handler

type Router struct {
	mu          sync.RWMutex
	handlers    map[string]Handler
	middlewares []Middleware
}

func NewRouter() *Router {
	return &Router{handlers: make(map[string]Handler)}
}

func (x *Router) Use(middleware Middleware) error {
	if x == nil || middleware == nil {
		return ErrAPI
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	x.middlewares = append(x.middlewares, middleware)
	return nil
}

func (x *Router) Handle(name string, handler Handler) error {
	if x == nil || name == "" || handler == nil {
		return ErrAPI
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	x.handlers[name] = handler
	return nil
}

func (x *Router) Dispatch(ctx context.Context, update tl.Dynamic) error {
	if x == nil || update.Name == "" {
		return ErrAPI
	}
	x.mu.RLock()
	handler := x.handlers[update.Name]
	middlewares := append([]Middleware(nil), x.middlewares...)
	x.mu.RUnlock()
	if handler == nil {
		return nil
	}
	for index := len(middlewares) - 1; index >= 0; index-- {
		handler = middlewares[index](handler)
		if handler == nil {
			return ErrAPI
		}
	}
	return handler(ctx, update)
}
