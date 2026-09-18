package plainidfasthttp_test

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/plainidio/plainid-go-authz/internal/authztest"
	plainidfasthttp "github.com/plainidio/plainid-go-authz/middleware/fasthttp"
	"github.com/plainidio/plainid-go-authz/plainid"
	"github.com/valyala/fasthttp"
)

// buildGateway wires the fasthttp adapter the way a real deployment would:
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
	authorize, err := plainidfasthttp.Middleware(cfg, plainidfasthttp.WithSkip(
		func(ctx *fasthttp.RequestCtx) bool { return string(ctx.Path()) == "/healthz" },
	))
	if err != nil {
		t.Fatalf("building middleware: %v", err)
	}

	handler := authorize(func(ctx *fasthttp.RequestCtx) {
		if string(ctx.Path()) == "/healthz" {
			ctx.SetBodyString("ok")
			return
		}
		record(ctx, backend)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &fasthttp.Server{Handler: handler}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Shutdown() })

	return authztest.Gateway{
		URL:            "http://" + ln.Addr().String(),
		PDP:            pdp,
		Backend:        backend,
		UnenforcedPath: "/healthz",
	}
}

// record is the fasthttp equivalent of authztest.Backend's own net/http
// handler: it notes what actually reached the backend, in the neutral shape
// the contract suite inspects.
func record(ctx *fasthttp.RequestCtx, backend *authztest.Backend) {
	header := http.Header{}
	ctx.Request.Header.VisitAll(func(k, v []byte) {
		header.Add(string(k), string(v))
	})
	backend.Record(authztest.Hit{
		Method: string(ctx.Method()),
		Path:   string(ctx.Path()),
		Query:  string(ctx.URI().QueryString()),
		Header: header,
		Body:   string(ctx.PostBody()),
	})
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(http.StatusOK)
	ctx.SetBodyString(`{"backend":true}`)
}

// TestContract runs the same suite the net/http adapter passes. Nothing about
// the decision is reimplemented here, so this is really a check that the
// translation layer is faithful.
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
