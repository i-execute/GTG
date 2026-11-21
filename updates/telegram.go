package updates

import (
	"context"
	"errors"
	"math"

	"github.com/i-execute/GTG/entities"
	"github.com/i-execute/GTG/internal/tlgen"
	"github.com/i-execute/GTG/tl"
)

var ErrTelegramDifference = errors.New("gtg: invalid telegram difference")

type Caller interface {
	Call(context.Context, tl.Dynamic) (tl.Dynamic, error)
}

func NewTelegramFetcher(caller Caller, cache *entities.Cache) Fetcher {
	if caller == nil {
		return nil
	}
	return func(ctx context.Context, from Snapshot) (Difference, error) {
		if from.PTS > math.MaxInt32 || from.QTS > math.MaxInt32 || from.Date > math.MaxInt32 {
			return Difference{}, ErrTelegramDifference
		}
		request := tlgen.MethodUpdatesGetDifference_19C2F763{
			FFlags1: 0,
			FPts2:   int32(from.PTS),
			FDate5:  int32(from.Date),
			FQts6:   int32(from.QTS),
		}.Request()
		value, err := caller.Call(ctx, request)
		if err != nil {
			return Difference{}, err
		}
		if cache != nil {
			if err := cache.Ingest(value); err != nil {
				return Difference{}, err
			}
		}
		return telegramDifference(ctx, caller, value, from)
	}
}

func NewTelegramEngine(state *State, caller Caller, cache *entities.Cache, handle Handler) (*Engine, error) {
	fetch := NewTelegramFetcher(caller, cache)
	if caller == nil {
		return nil, ErrTelegramDifference
	}
	engine, err := NewEngine(state, fetch, handle)
	if err != nil || cache == nil {
		return engine, err
	}
	engine.observe = func(ctx context.Context, value tl.Dynamic) error {
		return cache.Ingest(value)
	}
	return engine, nil
}

func telegramDifference(ctx context.Context, caller Caller, value tl.Dynamic, from Snapshot) (Difference, error) {
	switch value.Name {
	case "updates.difference":
		state, ok := snapshot(value.Fields["state"])
		if !ok {
			return Difference{}, ErrTelegramDifference
		}
		return Difference{Updates: updatesField(value.Fields["other_updates"]), State: state, Final: true}, nil
	case "updates.differenceSlice":
		state, ok := snapshot(value.Fields["intermediate_state"])
		if !ok {
			return Difference{}, ErrTelegramDifference
		}
		return Difference{Updates: updatesField(value.Fields["other_updates"]), State: state, Final: false}, nil
	case "updates.differenceEmpty":
		state := from
		date, dateOK := telegramInt(value.Fields["date"])
		sequence, sequenceOK := telegramInt(value.Fields["seq"])
		if !dateOK || !sequenceOK || date < from.Date || sequence < from.Seq {
			return Difference{}, ErrTelegramDifference
		}
		state.Date = date
		state.Seq = sequence
		return Difference{State: state, Final: true}, nil
	case "updates.differenceTooLong":
		return telegramState(ctx, caller)
	default:
		return Difference{}, ErrTelegramDifference
	}
}

func telegramState(ctx context.Context, caller Caller) (Difference, error) {
	value, err := caller.Call(ctx, tlgen.NewMethodUpdatesGetState_EDD4882A().Request())
	if err != nil {
		return Difference{}, err
	}
	state, ok := snapshot(value)
	if !ok {
		return Difference{}, ErrTelegramDifference
	}
	return Difference{State: state, Final: true}, nil
}

func updatesField(value any) []tl.Dynamic {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]tl.Dynamic, 0, len(raw))
	for _, item := range raw {
		if update, ok := item.(tl.Dynamic); ok {
			result = append(result, update)
		}
	}
	return result
}

func snapshot(value any) (Snapshot, bool) {
	dynamic, ok := value.(tl.Dynamic)
	if !ok || dynamic.Name != "updates.state" {
		return Snapshot{}, false
	}
	pts, ptsOK := telegramInt(dynamic.Fields["pts"])
	qts, qtsOK := telegramInt(dynamic.Fields["qts"])
	date, dateOK := telegramInt(dynamic.Fields["date"])
	sequence, sequenceOK := telegramInt(dynamic.Fields["seq"])
	if !ptsOK || !qtsOK || !dateOK || !sequenceOK || pts < 0 || qts < 0 || date < 0 || sequence < 0 {
		return Snapshot{}, false
	}
	return Snapshot{PTS: pts, QTS: qts, Date: date, Seq: sequence}, true
}

func telegramInt(value any) (int, bool) {
	switch value := value.(type) {
	case int:
		return value, value >= 0
	case int32:
		return int(value), value >= 0
	case int64:
		if value < 0 || value > math.MaxInt {
			return 0, false
		}
		return int(value), true
	}
	return 0, false
}
