// Package authztest provides the shared acceptance suite every framework
// adapter must pass, plus the stub PDP and backend it drives.
//
// A new adapter — fasthttp, gin, echo — wires its own server around
// Backend and StubPDP and calls RunContract. That way each port is checked for
// the things that are invisible when they go wrong: failing closed, denials
// that leak nothing, request-id correlation, and denied requests never
// reaching the backend.
package authztest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Identities the stub PDP knows about, used as bearer tokens.
const (
	Admin     = "orders-admin"  // any method under /api/v1/orders
	Reader    = "orders-reader" // GET only, under /api/v1/orders
	Anonymous = ""              // no token at all
)

// Call is one decision request the stub PDP received.
type Call struct {
	Payload   map[string]any
	Header    http.Header
	RequestID string
}

// StubPDP is a PlainID PDP stand-in. It applies a small fixed policy, and
// asserts the decision payload's shape on every call — the path array in
// particular, which is the detail most easily got wrong in a new adapter.
type StubPDP struct {
	server *httptest.Server

	mu       sync.Mutex
	calls    []Call
	status   int
	body     string
	override bool
}

// NewStubPDP starts a stub PDP and stops it when the test ends.
func NewStubPDP(t *testing.T) *StubPDP {
	t.Helper()
	p := &StubPDP{}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.serve(t, w, r)
	}))
	t.Cleanup(p.server.Close)
	return p
}

// URL is the base URL to configure as PLAINID_URL.
func (p *StubPDP) URL() string { return p.server.URL }

// Stop shuts the PDP down, to prove the gateway fails closed without it.
func (p *StubPDP) Stop() { p.server.Close() }

// SetResponse makes the PDP answer with a fixed status and body, for the
// malformed and error cases.
func (p *StubPDP) SetResponse(status int, body string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status, p.body, p.override = status, body, true
}

// ClearResponse restores the policy behaviour.
func (p *StubPDP) ClearResponse() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.override = false
}

// Calls returns every decision request received so far.
func (p *StubPDP) Calls() []Call {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Call(nil), p.calls...)
}

// Reset forgets recorded calls.
func (p *StubPDP) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = nil
}

const decisionPath = "/runtime/5.0/decisions/permit-deny"

func (p *StubPDP) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	if r.URL.Path != decisionPath {
		t.Errorf("PDP called at %q, want %q", r.URL.Path, decisionPath)
	}

	raw, _ := io.ReadAll(r.Body)
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decision payload is not JSON: %v (%s)", err, raw)
	}
	p.checkPayloadShape(t, payload)

	p.mu.Lock()
	p.calls = append(p.calls, Call{
		Payload:   payload,
		Header:    r.Header.Clone(),
		RequestID: r.Header.Get("X-Request-ID"),
	})
	status, body, override := p.status, p.body, p.override
	p.mu.Unlock()

	if override {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
		return
	}

	result := "DENY"
	if permits(token(r), method(payload), fullPath(payload)) {
		result = "PERMIT"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"result": result}})
}

// checkPayloadShape asserts the parts of the wire format that a new adapter is
// most likely to get subtly wrong.
func (p *StubPDP) checkPayloadShape(t *testing.T, payload map[string]any) {
	t.Helper()

	uri, ok := payload["uri"].(map[string]any)
	if !ok {
		t.Fatalf("payload has no uri object: %#v", payload)
	}
	raw, ok := uri["path"].([]any)
	if !ok || len(raw) == 0 {
		t.Fatalf("payload has no uri.path array: %#v", uri)
	}
	path := make([]string, len(raw))
	for i, v := range raw {
		path[i], _ = v.(string)
	}
	// Index 0 is the full path; the rest are its segments, with no empty
	// entry for the leading slash.
	want := strings.Split(strings.TrimPrefix(path[0], "/"), "/")
	if got := path[1:]; !equal(got, want) {
		t.Errorf("uri.path = %#v, want [%q] followed by %#v", path, path[0], want)
	}
	if _, ok := uri["schema"]; !ok {
		t.Errorf(`uri has no "schema" key (note the spelling): %#v`, uri)
	}
	if _, ok := uri["query"]; !ok {
		t.Errorf("uri has no query object: %#v", uri)
	}
	if _, ok := payload["meta"].(map[string]any)["runtimeFineTune"]; !ok {
		t.Errorf("payload has no meta.runtimeFineTune: %#v", payload["meta"])
	}
	for name := range payload["headers"].(map[string]any) {
		if name != strings.ToLower(name) {
			t.Errorf("payload header name %q is not lower-cased", name)
		}
	}
	if m, _ := payload["method"].(string); m != strings.ToUpper(m) {
		t.Errorf("payload method %q is not upper-cased", m)
	}
}

// permits is the stub policy: admins may do anything under /api/v1/orders,
// readers may only read there, and everyone else is denied.
func permits(token, method, path string) bool {
	switch token {
	case Admin:
		return strings.HasPrefix(path, "/api/v1/orders")
	case Reader:
		return method == http.MethodGet && strings.HasPrefix(path, "/api/v1/orders")
	default:
		return false
	}
}

func token(r *http.Request) string {
	return strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
}

func method(payload map[string]any) string {
	m, _ := payload["method"].(string)
	return m
}

func fullPath(payload map[string]any) string {
	uri, _ := payload["uri"].(map[string]any)
	path, _ := uri["path"].([]any)
	if len(path) == 0 {
		return ""
	}
	s, _ := path[0].(string)
	return s
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
