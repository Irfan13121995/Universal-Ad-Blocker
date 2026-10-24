package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"sinkhole/src/server/stats"
	"sinkhole/src/store"
)

// Hub fans live query events and counters out to Server-Sent-Event clients.
// Events are batched once per second so a busy network cannot flood browsers.
type Hub struct {
	stats *stats.Stats

	mu   sync.Mutex
	subs map[chan []byte]struct{}
	buf  []store.QueryEntry
}

// NewHub creates a hub.
func NewHub(s *stats.Stats) *Hub {
	return &Hub{stats: s, subs: map[chan []byte]struct{}{}}
}

// Publish implements server.Publisher.
func (h *Hub) Publish(e store.QueryEntry) {
	h.mu.Lock()
	if len(h.subs) > 0 && len(h.buf) < 500 {
		h.buf = append(h.buf, e)
	}
	h.mu.Unlock()
}

type ssePayload struct {
	Counters stats.Counters     `json:"counters"`
	Queries  []store.QueryEntry `json:"queries"`
}

// Run broadcasts every second until ctx is done.
func (h *Hub) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		h.mu.Lock()
		if len(h.subs) == 0 {
			h.buf = h.buf[:0]
			h.mu.Unlock()
			continue
		}
		p := ssePayload{Counters: h.stats.Counters(), Queries: h.buf}
		h.buf = nil
		b, err := json.Marshal(p)
		if err == nil {
			for ch := range h.subs {
				select {
				case ch <- b:
				default: // slow client: skip this tick
				}
			}
		}
		h.mu.Unlock()
	}
}

// ServeHTTP streams events to one client.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan []byte, 4)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}()

	fmt.Fprint(w, "retry: 3000\n\n")
	fl.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-ch:
			if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
				return
			}
			fl.Flush()
		}
	}
}
