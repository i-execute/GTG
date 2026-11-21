package entities

import (
	"strings"

	"github.com/i-execute/GTG/tl"
)

func (x *Cache) Ingest(value tl.Dynamic) error {
	if x == nil {
		return ErrEntity
	}
	return x.ingest(value)
}

func (x *Cache) ingest(value tl.Dynamic) error {
	if entity, ok := dynamicEntity(value); ok {
		if previous, exists := x.GetID(entity.ID); exists && entity.Min {
			if entity.AccessHash == 0 {
				entity.AccessHash = previous.AccessHash
			}
			if entity.Username == "" {
				entity.Username = previous.Username
			}
			if entity.Phone == "" {
				entity.Phone = previous.Phone
			}
		}
		if err := x.Put(entity); err != nil {
			return err
		}
	}
	for _, field := range value.Fields {
		if err := x.ingestValue(field); err != nil {
			return err
		}
	}
	return nil
}

func (x *Cache) ingestValue(value any) error {
	switch value := value.(type) {
	case tl.Dynamic:
		return x.ingest(value)
	case []any:
		for _, item := range value {
			if err := x.ingestValue(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func dynamicEntity(value tl.Dynamic) (Entity, bool) {
	kind := Kind(0)
	switch value.Name {
	case "user":
		kind = User
	case "chat":
		kind = Chat
	case "channel":
		kind = Channel
	default:
		return Entity{}, false
	}
	id, ok := entityInt(value.Fields["id"])
	if !ok || id == 0 {
		return Entity{}, false
	}
	access, _ := entityInt(value.Fields["access_hash"])
	username, _ := value.Fields["username"].(string)
	phone, _ := value.Fields["phone"].(string)
	minimum, _ := value.Fields["min"].(bool)
	return Entity{ID: id, AccessHash: access, Username: username, Phone: phone, Kind: kind, Min: minimum}, true
}

func entityInt(value any) (int64, bool) {
	switch value := value.(type) {
	case int64:
		return value, true
	case int32:
		return int64(value), true
	case int:
		return int64(value), true
	}
	return 0, false
}

func InputPeer(value Entity) (tl.Dynamic, error) {
	if !valid(value) {
		return tl.Dynamic{}, ErrEntity
	}
	switch value.Kind {
	case User:
		if value.AccessHash == 0 {
			return tl.Dynamic{}, ErrEntity
		}
		return tl.Dynamic{Name: "inputPeerUser", Fields: map[string]any{"user_id": value.ID, "access_hash": value.AccessHash}}, nil
	case Chat:
		return tl.Dynamic{Name: "inputPeerChat", Fields: map[string]any{"chat_id": value.ID}}, nil
	case Channel:
		if value.AccessHash == 0 {
			return tl.Dynamic{}, ErrEntity
		}
		return tl.Dynamic{Name: "inputPeerChannel", Fields: map[string]any{"channel_id": value.ID, "access_hash": value.AccessHash}}, nil
	}
	return tl.Dynamic{}, ErrEntity
}

func (x *Cache) PeerByID(id int64) (tl.Dynamic, bool) {
	value, ok := x.GetID(id)
	if !ok {
		return tl.Dynamic{}, false
	}
	peer, err := InputPeer(value)
	return peer, err == nil
}

func (x *Cache) PeerByUsername(username string) (tl.Dynamic, bool) {
	if strings.TrimSpace(username) == "" {
		return tl.Dynamic{}, false
	}
	value, ok := x.GetUsername(username)
	if !ok {
		return tl.Dynamic{}, false
	}
	peer, err := InputPeer(value)
	return peer, err == nil
}
