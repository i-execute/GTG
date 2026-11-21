package core

import (
	"errors"
	"runtime"
	"sync"
)

var ErrMTProtoPool = errors.New("gtg: MTProto pool unavailable")

type MTProtoPacketStream struct {
	Box       *MTProto
	Packet    []byte
	Direction Direction
	Open      bool
	Payload   []byte
	Err       error
}

type MTProtoPool struct {
	mu         sync.Mutex
	work       *sync.Cond
	finished   *sync.Cond
	streams    []MTProtoPacketStream
	next       int
	pending    int
	generation uint64
	active     bool
	closed     bool
	workers    int
}

func NewMTProtoPool(workers int) (*MTProtoPool, error) {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers <= 0 {
		return nil, ErrMTProtoPool
	}
	pool := &MTProtoPool{workers: workers}
	pool.work = sync.NewCond(&pool.mu)
	pool.finished = sync.NewCond(&pool.mu)
	for range workers {
		go pool.run()
	}
	return pool, nil
}

func (p *MTProtoPool) Process(streams []MTProtoPacketStream) error {
	p.mu.Lock()
	if p.closed || p.active {
		p.mu.Unlock()
		return ErrMTProtoPool
	}
	for i := range streams {
		if streams[i].Box == nil {
			p.mu.Unlock()
			return ErrMTProtoPool
		}
		streams[i].Payload = nil
		streams[i].Err = nil
	}
	p.streams = streams
	p.next = 0
	p.pending = p.workers
	p.active = true
	p.generation++
	p.work.Broadcast()
	for p.pending != 0 {
		p.finished.Wait()
	}
	var err error
	for i := range streams {
		if streams[i].Err != nil {
			err = ErrMTProtoPacket
			break
		}
	}
	p.streams = nil
	p.active = false
	p.mu.Unlock()
	return err
}

func (p *MTProtoPool) Close() {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.work.Broadcast()
	}
	p.mu.Unlock()
}

func (p *MTProtoPool) run() {
	var seen uint64
	for {
		p.mu.Lock()
		for !p.closed && p.generation == seen {
			p.work.Wait()
		}
		if p.closed {
			p.mu.Unlock()
			return
		}
		seen = p.generation
		for {
			if p.next == len(p.streams) {
				p.pending--
				if p.pending == 0 {
					p.finished.Signal()
				}
				p.mu.Unlock()
				break
			}
			index := p.next
			p.next++
			stream := &p.streams[index]
			p.mu.Unlock()
			if stream.Open {
				stream.Payload, stream.Err = stream.Box.OpenInPlace(stream.Packet, stream.Direction)
			} else {
				stream.Packet, stream.Err = stream.Box.SealInPlace(stream.Packet, stream.Direction)
			}
			p.mu.Lock()
		}
	}
}
