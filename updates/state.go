package updates

import (
	"encoding/binary"
	"errors"
	"sync"

	"github.com/i-execute/GTG/vault"
)

var ErrState = errors.New("gtg: invalid update state")

type Snapshot struct {
	PTS  int
	QTS  int
	Date int
	Seq  int
}

type Gap struct {
	Have     int
	WantFrom int
	WantTo   int
}

func (x *Gap) Error() string {
	return "gtg: updates gap"
}

type State struct {
	mu       sync.Mutex
	snapshot Snapshot
}

func New(snapshot Snapshot) (*State, error) {
	if !valid(snapshot) {
		return nil, ErrState
	}
	return &State{snapshot: snapshot}, nil
}

func (x *State) Snapshot() Snapshot {
	if x == nil {
		return Snapshot{}
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.snapshot
}

func (x *State) Replace(snapshot Snapshot) error {
	if x == nil || !valid(snapshot) {
		return ErrState
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if snapshot.PTS < x.snapshot.PTS || snapshot.QTS < x.snapshot.QTS || snapshot.Date < x.snapshot.Date || snapshot.Seq < x.snapshot.Seq {
		return ErrState
	}
	x.snapshot = snapshot
	return nil
}

func (x *State) ApplyPTS(pts, count int) error {
	if x == nil || pts < 0 || count < 0 || count > pts {
		return ErrState
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if pts <= x.snapshot.PTS {
		return nil
	}
	if count != 0 && pts-count != x.snapshot.PTS {
		return &Gap{Have: x.snapshot.PTS, WantFrom: x.snapshot.PTS + count, WantTo: pts}
	}
	x.snapshot.PTS = pts
	return nil
}

func (x *State) ApplyQTS(qts int) error {
	if x == nil || qts < 0 {
		return ErrState
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if qts > x.snapshot.QTS {
		x.snapshot.QTS = qts
	}
	return nil
}

func (x *State) ApplySeq(seq, date int) error {
	return x.ApplySeqRange(seq, seq, date)
}

func (x *State) ApplySeqRange(start, end, date int) error {
	if x == nil || start < 0 || end < 0 || date < 0 || start > end || start == 0 && end != 0 || start != 0 && end == 0 {
		return ErrState
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if start != 0 && x.snapshot.Seq != 0 && start != x.snapshot.Seq+1 {
		return &Gap{Have: x.snapshot.Seq, WantFrom: x.snapshot.Seq + 1, WantTo: end}
	}
	if end > x.snapshot.Seq {
		x.snapshot.Seq = end
	}
	if date > x.snapshot.Date {
		x.snapshot.Date = date
	}
	return nil
}

func (x *State) Store(target *vault.Vault, name string) error {
	if x == nil || target == nil || name == "" {
		return ErrState
	}
	value := x.Snapshot()
	data := encode(value)
	err := target.Put("updates-"+name, data)
	clear(data)
	return err
}

func Load(target *vault.Vault, name string) (*State, error) {
	if target == nil || name == "" {
		return nil, ErrState
	}
	secret, err := target.Get("updates-" + name)
	if err != nil {
		return nil, err
	}
	data, err := secret.Bytes()
	secret.Destroy()
	if err != nil {
		return nil, err
	}
	value, err := decode(data)
	clear(data)
	if err != nil {
		return nil, err
	}
	return New(value)
}

func encode(value Snapshot) []byte {
	data := make([]byte, 20)
	data[0] = 1
	binary.LittleEndian.PutUint32(data[4:8], uint32(value.PTS))
	binary.LittleEndian.PutUint32(data[8:12], uint32(value.QTS))
	binary.LittleEndian.PutUint32(data[12:16], uint32(value.Date))
	binary.LittleEndian.PutUint32(data[16:20], uint32(value.Seq))
	return data
}

func decode(data []byte) (Snapshot, error) {
	if len(data) != 20 || data[0] != 1 || data[1] != 0 || data[2] != 0 || data[3] != 0 {
		return Snapshot{}, ErrState
	}
	value := Snapshot{PTS: int(binary.LittleEndian.Uint32(data[4:8])), QTS: int(binary.LittleEndian.Uint32(data[8:12])), Date: int(binary.LittleEndian.Uint32(data[12:16])), Seq: int(binary.LittleEndian.Uint32(data[16:20]))}
	if !valid(value) {
		return Snapshot{}, ErrState
	}
	return value, nil
}

func valid(value Snapshot) bool {
	return value.PTS >= 0 && value.QTS >= 0 && value.Date >= 0 && value.Seq >= 0
}
