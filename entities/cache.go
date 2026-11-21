package entities

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/i-execute/GTG/vault"
)

var ErrEntity = errors.New("gtg: invalid entity")

type Kind uint8

const (
	User Kind = iota + 1
	Chat
	Channel
)

type Entity struct {
	ID         int64  `json:"id"`
	AccessHash int64  `json:"access_hash"`
	Username   string `json:"username"`
	Phone      string `json:"phone"`
	Kind       Kind   `json:"kind"`
	Min        bool   `json:"min"`
}

type Cache struct {
	mu         sync.RWMutex
	byID       map[int64]Entity
	byUsername map[string]int64
}

func New() *Cache {
	return &Cache{byID: make(map[int64]Entity), byUsername: make(map[string]int64)}
}

func (x *Cache) Put(value Entity) error {
	if x == nil || !valid(value) {
		return ErrEntity
	}
	value.Username = normalize(value.Username)
	x.mu.Lock()
	defer x.mu.Unlock()
	if previous, ok := x.byID[value.ID]; ok && previous.Username != "" && previous.Username != value.Username {
		delete(x.byUsername, previous.Username)
	}
	x.byID[value.ID] = value
	if value.Username != "" {
		x.byUsername[value.Username] = value.ID
	}
	return nil
}

func (x *Cache) GetID(id int64) (Entity, bool) {
	if x == nil {
		return Entity{}, false
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	value, ok := x.byID[id]
	return value, ok
}

func (x *Cache) GetUsername(username string) (Entity, bool) {
	if x == nil {
		return Entity{}, false
	}
	name := normalize(username)
	x.mu.RLock()
	defer x.mu.RUnlock()
	id, ok := x.byUsername[name]
	if !ok {
		return Entity{}, false
	}
	value, ok := x.byID[id]
	return value, ok
}

func (x *Cache) Delete(id int64) {
	if x == nil {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	value, ok := x.byID[id]
	if !ok {
		return
	}
	delete(x.byID, id)
	if value.Username != "" {
		delete(x.byUsername, value.Username)
	}
}

func (x *Cache) Snapshot() []Entity {
	if x == nil {
		return nil
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	result := make([]Entity, 0, len(x.byID))
	for _, value := range x.byID {
		result = append(result, value)
	}
	sortEntities(result)
	return result
}

func (x *Cache) Store(target *vault.Vault, name string) error {
	if x == nil || target == nil || name == "" {
		return ErrEntity
	}
	data, err := json.Marshal(x.Snapshot())
	if err != nil {
		return err
	}
	err = target.Put("entities-"+name, data)
	clear(data)
	return err
}

func Load(target *vault.Vault, name string) (*Cache, error) {
	if target == nil || name == "" {
		return nil, ErrEntity
	}
	secret, err := target.Get("entities-" + name)
	if err != nil {
		return nil, err
	}
	data, err := secret.Bytes()
	secret.Destroy()
	if err != nil {
		return nil, err
	}
	var values []Entity
	err = json.Unmarshal(data, &values)
	clear(data)
	if err != nil {
		return nil, ErrEntity
	}
	result := New()
	for _, value := range values {
		if err := result.Put(value); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func valid(value Entity) bool {
	return value.ID != 0 && value.Kind >= User && value.Kind <= Channel && !strings.ContainsAny(value.Username, "\x00 \t\r\n") && !strings.ContainsAny(value.Phone, "\x00\r\n")
}

func normalize(value string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "@"))
}

func sortEntities(values []Entity) {
	for index := 1; index < len(values); index++ {
		for cursor := index; cursor > 0 && values[cursor].ID < values[cursor-1].ID; cursor-- {
			values[cursor], values[cursor-1] = values[cursor-1], values[cursor]
		}
	}
}
