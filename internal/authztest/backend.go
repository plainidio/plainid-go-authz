package authztest

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
)

// Hit is one request that reached the backend. Its presence is the proof that
// matters: a gateway that denies *after* proxying is not enforcing anything.
type Hit struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   string
}

// Backend stands in for the service behind the gateway.
//
// Adapters built on net/http can use Handler directly. An adapter for another
// framework serves its own handler and calls Record, so the same contract
// checks still apply.
type Backend struct {
	mu   sync.Mutex
	hits []Hit
}

// NewBackend returns an empty backend recorder.
func NewBackend() *Backend { return &Backend{} }

// Handler records the request and answers with a recognizable body.
func (b *Backend) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		b.Record(Hit{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.RawQuery,
			Header: r.Header.Clone(),
			Body:   string(body),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"backend": true, "path": r.URL.Path})
	})
}

// Record notes a request that reached the backend.
func (b *Backend) Record(h Hit) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hits = append(b.hits, h)
}

// Hits returns everything the backend has seen.
func (b *Backend) Hits() []Hit {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Hit(nil), b.hits...)
}

// Last returns the most recent hit, or false when the backend was never
// reached.
func (b *Backend) Last() (Hit, bool) {
	hits := b.Hits()
	if len(hits) == 0 {
		return Hit{}, false
	}
	return hits[len(hits)-1], true
}

// Reset forgets recorded hits.
func (b *Backend) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hits = nil
}
