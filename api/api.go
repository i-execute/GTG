package api

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"strings"

	"github.com/i-execute/GTG/entities"
	"github.com/i-execute/GTG/internal/tlgen"
	"github.com/i-execute/GTG/tl"
)

var ErrAPI = errors.New("gtg: invalid API request")

type Invoker interface {
	Call(context.Context, tl.Dynamic) (tl.Dynamic, error)
}

type Client struct {
	invoke   Invoker
	entities *entities.Cache
}

func New(invoke Invoker) (*Client, error) {
	return NewWithEntities(invoke, nil)
}

func NewWithEntities(invoke Invoker, cache *entities.Cache) (*Client, error) {
	if invoke == nil {
		return nil, ErrAPI
	}
	return &Client{invoke: invoke, entities: cache}, nil
}

func EscapeMarkdownV2(value string) string {
	return strings.NewReplacer("_", "\\_", "*", "\\*", "[", "\\[", "]", "\\]", "(", "\\(", ")", "\\)", "~", "\\~", "`", "\\`", ">", "\\>", "#", "\\#", "+", "\\+", "-", "\\-", "=", "\\=", "|", "\\|", "{", "\\{", "}", "\\}", ".", "\\.", "!", "\\!").Replace(value)
}

func (x *Client) SendSaved(ctx context.Context, text string) (tl.Dynamic, error) {
	return x.send(ctx, tlgen.NewConstructorInputPeerSelf_7DA07EC9().Dynamic(), text)
}

func (x *Client) SendTo(ctx context.Context, id int64, text string) (tl.Dynamic, error) {
	if x == nil || x.entities == nil {
		return tl.Dynamic{}, ErrAPI
	}
	peer, ok := x.entities.PeerByID(id)
	if !ok {
		return tl.Dynamic{}, ErrAPI
	}
	return x.send(ctx, peer, text)
}

func (x *Client) SendToUsername(ctx context.Context, username, text string) (tl.Dynamic, error) {
	if x == nil || x.entities == nil {
		return tl.Dynamic{}, ErrAPI
	}
	peer, ok := x.entities.PeerByUsername(username)
	if !ok {
		var err error
		peer, err = x.ResolveUsername(ctx, username)
		if err != nil {
			return tl.Dynamic{}, err
		}
	}
	return x.send(ctx, peer, text)
}

func (x *Client) ResolveUsername(ctx context.Context, username string) (tl.Dynamic, error) {
	if x == nil || x.invoke == nil || x.entities == nil || strings.TrimSpace(username) == "" {
		return tl.Dynamic{}, ErrAPI
	}
	value, err := x.invoke.Call(ctx, tlgen.MethodContactsResolveUsername_725AFBBC{FFlags1: 0, FUsername2: username}.Request())
	if err != nil {
		return tl.Dynamic{}, err
	}
	if err := x.entities.Ingest(value); err != nil {
		return tl.Dynamic{}, err
	}
	peer, ok := x.entities.PeerByUsername(username)
	if !ok {
		return tl.Dynamic{}, ErrAPI
	}
	return peer, nil
}

func (x *Client) SavedHistory(ctx context.Context, offsetID, limit int) (tl.Dynamic, error) {
	if x == nil || x.invoke == nil || offsetID < 0 || offsetID > math.MaxInt32 || limit < 1 || limit > 100 {
		return tl.Dynamic{}, ErrAPI
	}
	return x.invoke.Call(ctx, tlgen.MethodMessagesGetHistory_4423E6C5{
		FPeer1:       tlgen.NewConstructorInputPeerSelf_7DA07EC9().Dynamic(),
		FOffsetId2:   int32(offsetID),
		FOffsetDate3: 0,
		FAddOffset4:  0,
		FLimit5:      int32(limit),
		FMaxId6:      0,
		FMinId7:      0,
		FHash8:       0,
	}.Request())
}

func (x *Client) Dialogs(ctx context.Context, limit int) (tl.Dynamic, error) {
	if x == nil || x.invoke == nil || limit < 1 || limit > 100 {
		return tl.Dynamic{}, ErrAPI
	}
	return x.invoke.Call(ctx, tlgen.MethodMessagesGetDialogs_A0F4CB4F{
		FFlags1:      0,
		FOffsetDate4: 0,
		FOffsetId5:   0,
		FOffsetPeer6: tlgen.NewConstructorInputPeerEmpty_7F3B18EA().Dynamic(),
		FLimit7:      int32(limit),
		FHash8:       0,
	}.Request())
}

func (x *Client) send(ctx context.Context, peer tl.Dynamic, text string) (tl.Dynamic, error) {
	if x == nil || x.invoke == nil || peer.Name == "" || text == "" {
		return tl.Dynamic{}, ErrAPI
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return tl.Dynamic{}, err
	}
	randomID := int64(binary.LittleEndian.Uint64(raw[:]))
	clear(raw[:])
	return x.invoke.Call(ctx, tlgen.MethodMessagesSendMessage_FEF48F62{
		FFlags1:     0,
		FPeer10:     peer,
		FMessage12:  text,
		FRandomId13: randomID,
	}.Request())
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
