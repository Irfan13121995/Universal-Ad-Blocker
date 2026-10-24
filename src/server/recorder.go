package server

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"sinkhole/src/server/stats"
	"sinkhole/src/store"
)

// Publisher receives every query for live streaming (implemented by the web hub).
type Publisher interface {
	Publish(store.QueryEntry)
}

// Recorder decouples the DNS hot path from statistics, SQLite persistence and
// live streaming: ServeDNS performs a non-blocking channel send and a single
// goroutine does the rest, batching inserts into one transaction per second.
type Recorder struct {
	ch      chan store.QueryEntry
	st      *store.Store
	stats   *stats.Stats
	log     *slog.Logger
	persist atomic.Bool
	dropped atomic.Int64

	pubMu sync.RWMutex
	pub   Publisher

	done chan struct{}
}

// NewRecorder creates a recorder.
func NewRecorder(st *store.Store, s *stats.Stats, log *slog.Logger, persist bool) *Recorder {
	r := &Recorder{ch: make(chan store.QueryEntry, 20000), st: st, stats: s, log: log, done: make(chan struct{})}
	r.persist.Store(persist)
	return r
}

// SetPublisher attaches the live stream hub.
func (r *Recorder) SetPublisher(p Publisher) {
	r.pubMu.Lock()
	r.pub = p
	r.pubMu.Unlock()
}

// SetPersist toggles writing queries to SQLite.
func (r *Recorder) SetPersist(v bool) { r.persist.Store(v) }

// Record enqueues an entry; it never blocks the DNS path.
func (r *Recorder) Record(e store.QueryEntry) {
	select {
	case r.ch <- e:
	default:
		r.dropped.Add(1)
	}
}

// Run processes entries until ctx is cancelled, then flushes and returns.
func (r *Recorder) Run(ctx context.Context) {
	defer close(r.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	batch := make([]store.QueryEntry, 0, 512)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := r.st.InsertQueries(batch); err != nil {
			r.log.Error("query log write failed", "err", err, "rows", len(batch))
		}
		batch = batch[:0]
	}
	handle := func(e store.QueryEntry) {
		r.stats.Record(e)
		r.pubMu.RLock()
		if r.pub != nil {
			r.pub.Publish(e)
		}
		r.pubMu.RUnlock()
		if r.persist.Load() {
			batch = append(batch, e)
			if len(batch) >= 2000 {
				flush()
			}
		}
	}
	for {
		select {
		case e := <-r.ch:
			handle(e)
		case <-tick.C:
			flush()
			if n := r.dropped.Swap(0); n > 0 {
				r.log.Warn("query log queue full; entries dropped", "count", n)
			}
		case <-ctx.Done():
			for {
				select {
				case e := <-r.ch:
					handle(e)
				default:
					flush()
					return
				}
			}
		}
	}
}

// Wait blocks until Run has returned.
func (r *Recorder) Wait() { <-r.done }
