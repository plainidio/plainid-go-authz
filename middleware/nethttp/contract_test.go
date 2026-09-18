package plainidhttp_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/plainidio/plainid-go-authz/internal/authztest"
	"github.com/plainidio/plainid-go-authz/middleware/nethttp"
	"github.com/plainidio/plainid-go-authz/plainid"
)

// buildGateway wires the net/http adapter the way a real deployment would:
// enforcement in front of a backend, deciding against a stub PDP, with one
// declared exclusion.
func buildGateway(t *testing.T) authztest.Gateway {
	t.Helper()
	pdp := authztest.NewStubPDP(t)
	backend := authztest.NewBackend()

	cfg := plainid.Config{
		URL:            pdp.URL(),
		ClientID:       "test-client",
		RequestTimeout: 2 * time.Second,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	authorize, err := plainidhttp.Middleware(cfg, plainidhttp.WithSkip(
		func(r *http.Request) bool { return r.URL.Path == "/healthz" },
	))
	if err != nil {
		t.Fatalf("building middleware: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	mux.Handle("/", backend.Handler())

	srv := httptest.NewServer(authorize(mux))
	t.Cleanup(srv.Close)

	return authztest.Gateway{
		URL:            srv.URL,
		PDP:            pdp,
		Backend:        backend,
		UnenforcedPath: "/healthz",
	}
}

// TestContract runs the suite every framework adapter must pass.
func TestContract(t *testing.T) {
	authztest.RunContract(t, buildGateway(t))
}

// TestFailsClosed is the check that never shows up on its own: with the PDP
// gone, everything must be refused.
func TestFailsClosed(t *testing.T) {
	gw := buildGateway(t)
	gw.PDP.Stop()
	authztest.RunFailsClosed(t, gw)
}
