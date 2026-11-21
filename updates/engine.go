package updates

import (
	"context"
	"errors"
	"sync"

	"github.com/i-execute/GTG/tl"
)

var ErrDifference = errors.New("gtg: update difference recovery failed")

type Difference struct {
	Updates []tl.Dynamic
	State   Snapshot
	Final   bool
}

type Fetcher func(context.Context, Snapshot) (Difference, error)
type Handler func(context.Context, tl.Dynamic) error

type Engine struct {
	mu          sync.Mutex
	state       *State
	fetch       Fetcher
	observe     Handler
	handle      Handler
	maxRecovery int
}

func NewEngine(state *State, fetch Fetcher, handle Handler) (*Engine, error) {
	if state == nil {
		return nil, ErrState
	}
	return &Engine{state: state, fetch: fetch, handle: handle, maxRecovery: 16}, nil
}

func (x *Engine) State() *State {
	if x == nil {
		return nil
	}
	return x.state
}

func (x *Engine) Apply(ctx context.Context, value tl.Dynamic) error {
	return x.ApplyBatch(ctx, []tl.Dynamic{value})
}

func (x *Engine) ApplyBatch(ctx context.Context, values []tl.Dynamic) error {
	if x == nil || x.state == nil {
		return ErrState
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	for _, value := range values {
		if err := x.apply(ctx, value); err != nil {
			return err
		}
	}
	return nil
}

func (x *Engine) Recover(ctx context.Context) error {
	if x == nil || x.state == nil {
		return ErrState
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.recover(ctx)
}

func (x *Engine) apply(ctx context.Context, value tl.Dynamic) error {
	if x.observe != nil {
		if err := x.observe(ctx, value); err != nil {
			return err
		}
	}
	switch value.Name {
	case "updates", "updatesCombined":
		return x.applyEnvelope(ctx, value)
	case "updateShort":
		date, ok := dynamicInt(value.Fields["date"])
		if !ok {
			return ErrState
		}
		if err := x.applySeq(ctx, 0, 0, date); err != nil {
			return err
		}
		update, ok := value.Fields["update"].(tl.Dynamic)
		if !ok {
			return ErrState
		}
		return x.applySingle(ctx, update)
	default:
		return x.applySingle(ctx, value)
	}
}

func (x *Engine) applyEnvelope(ctx context.Context, value tl.Dynamic) error {
	date, ok := dynamicInt(value.Fields["date"])
	if !ok {
		return ErrState
	}
	sequence, sequenceOK := dynamicInt(value.Fields["seq"])
	if !sequenceOK {
		return ErrState
	}
	start := sequence
	if value.Name == "updatesCombined" {
		var startOK bool
		start, startOK = dynamicInt(value.Fields["seq_start"])
		if !startOK {
			return ErrState
		}
	}
	if err := x.applySeq(ctx, start, sequence, date); err != nil {
		return err
	}
	updates, ok := dynamicUpdates(value.Fields["updates"])
	if !ok {
		return ErrState
	}
	for _, update := range updates {
		if err := x.applySingle(ctx, update); err != nil {
			return err
		}
	}
	return nil
}

func (x *Engine) applySingle(ctx context.Context, value tl.Dynamic) error {
	if err := x.applyCounters(ctx, value); err != nil {
		var gap *Gap
		if !errors.As(err, &gap) {
			return err
		}
		if err := x.recover(ctx); err != nil {
			return err
		}
		if err := x.applyCounters(ctx, value); err != nil {
			return err
		}
	}
	return x.dispatch(ctx, value)
}

func (x *Engine) applySeq(ctx context.Context, start, end, date int) error {
	if err := x.state.ApplySeqRange(start, end, date); err != nil {
		var gap *Gap
		if !errors.As(err, &gap) {
			return err
		}
		if err := x.recover(ctx); err != nil {
			return err
		}
		return x.state.ApplySeqRange(start, end, date)
	}
	return nil
}

func (x *Engine) recover(ctx context.Context) error {
	if x.fetch == nil {
		return ErrDifference
	}
	for attempt := 0; attempt < x.maxRecovery; attempt++ {
		difference, err := x.fetch(ctx, x.state.Snapshot())
		if err != nil {
			return err
		}
		for _, value := range difference.Updates {
			if err := x.apply(ctx, value); err != nil {
				return err
			}
		}
		if err := x.state.Replace(difference.State); err != nil {
			return err
		}
		if difference.Final {
			return nil
		}
	}
	return ErrDifference
}

func (x *Engine) dispatch(ctx context.Context, value tl.Dynamic) error {
	if x.handle == nil {
		return nil
	}
	return x.handle(ctx, value)
}

func (x *Engine) applyCounters(ctx context.Context, value tl.Dynamic) error {
	if pts, ok := dynamicInt(value.Fields["pts"]); ok {
		count, _ := dynamicInt(value.Fields["pts_count"])
		if err := x.state.ApplyPTS(pts, count); err != nil {
			return err
		}
	}
	if qts, ok := dynamicInt(value.Fields["qts"]); ok {
		if err := x.state.ApplyQTS(qts); err != nil {
			return err
		}
	}
	if sequence, ok := dynamicInt(value.Fields["seq"]); ok {
		date, _ := dynamicInt(value.Fields["date"])
		if err := x.applySeq(ctx, sequence, sequence, date); err != nil {
			return err
		}
	}
	return nil
}

func dynamicUpdates(value any) ([]tl.Dynamic, bool) {
	raw, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := make([]tl.Dynamic, 0, len(raw))
	for _, item := range raw {
		update, ok := item.(tl.Dynamic)
		if !ok {
			return nil, false
		}
		result = append(result, update)
	}
	return result, true
}

func dynamicInt(value any) (int, bool) {
	switch value := value.(type) {
	case int:
		return value, true
	case int32:
		return int(value), true
	case int64:
		if int64(int(value)) == value {
			return int(value), true
		}
	case uint32:
		return int(value), true
	}
	return 0, false
}
