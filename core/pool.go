package core

import (
	"errors"
	"sync"
)

var ErrIGEPoolWorkers = errors.New("gtg: worker count must be positive")
var ErrIGEPoolClosed = errors.New("gtg: worker pool is closed")

type IGEPool struct {
	mu     sync.Mutex
	jobs   syncChan
	done   chan struct{}
	wait   sync.WaitGroup
	closed bool
}

type syncChan chan igePoolJob

type igePoolJob struct {
	stream  *IGEKeyStream
	decrypt bool
}

func NewIGEPool(workers int) (*IGEPool, error) {
	if workers < 1 {
		return nil, ErrIGEPoolWorkers
	}
	x := &IGEPool{jobs: make(syncChan, workers), done: make(chan struct{}, workers)}
	x.wait.Add(workers)
	for range workers {
		go x.run()
	}
	return x, nil
}

func (x *IGEPool) Close() {
	x.mu.Lock()
	if x.closed {
		x.mu.Unlock()
		return
	}
	x.closed = true
	close(x.jobs)
	x.mu.Unlock()
	x.wait.Wait()
}

func (x *IGEPool) Encrypt(streams []IGEKeyStream) error {
	return x.transform(streams, false)
}

func (x *IGEPool) Decrypt(streams []IGEKeyStream) error {
	return x.transform(streams, true)
}

func (x *IGEPool) transform(streams []IGEKeyStream, decrypt bool) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return ErrIGEPoolClosed
	}
	if err := validateIGEKeyStreams(streams); err != nil {
		return err
	}
	sent := 0
	done := 0
	for done != len(streams) {
		var jobs chan igePoolJob
		var job igePoolJob
		if sent != len(streams) {
			jobs = x.jobs
			job = igePoolJob{stream: &streams[sent], decrypt: decrypt}
		}
		select {
		case jobs <- job:
			sent++
		case <-x.done:
			done++
		}
	}
	return nil
}

func (x *IGEPool) run() {
	defer x.wait.Done()
	for job := range x.jobs {
		if job.decrypt {
			_ = job.stream.IGE.Decrypt(job.stream.Dst, job.stream.Src, job.stream.IV)
		} else {
			_ = job.stream.IGE.Encrypt(job.stream.Dst, job.stream.Src, job.stream.IV)
		}
		x.done <- struct{}{}
	}
}
