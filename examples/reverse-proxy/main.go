// Command reverse-proxy is a net/http/httputil.ReverseProxy that authorizes
// every request against PlainID before it is forwarded upstream.
//
//	export PLAINID_URL=https://tenant.plainid.io/api
//	export PLAINID_CLIENT_ID=...
//	export UPSTREAM_URL=http://localhost:9000
//	go run ./examples/reverse-proxy
//
//	curl -i -H 'Authorization: Bearer <token>' localhost:8080/api/v1/orders/42
//
// A denied request is refused here and never reaches the upstream — the
// decision happens in the middleware, which wraps the proxy, so the proxy is
// only ever invoked on PERMIT.
//
// It also shows a middleware chain: requestLogger runs outside the PlainID
// middleware, so it observes denials as well as forwarded calls.
package main

import (
	"bufio"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	plainidhttp "github.com/plainidio/plainid-go-authz/middleware/nethttp"
	"github.com/plainidio/plainid-go-authz/plainid"
)

func main() {
	upstream, err := url.Parse(env("UPSTREAM_URL", "http://localhost:9000"))
	if err != nil {
		log.Fatalf("UPSTREAM_URL: %v", err)
	}

	cfg, err := plainid.ConfigFromEnv()
	if err != nil {
		log.Fatalf("configuration: %v", err)
	}
	if os.Getenv("PLAINID_REQUEST_TIMEOUT") == "" {
		cfg.RequestTimeout = 5 * time.Second
	}
	cfg.Logger = slog.New(slog.NewTextHandler(os.Stdout, nil))

	// This proxy terminates the caller's connection itself, so the caller's
	// real address is RemoteAddr. Set PLAINID_TRUST_FORWARDED_HEADERS=true
	// only when something you control (a load balancer) sits in front and
	// sets X-Forwarded-For — otherwise the caller can choose the address the
	// PDP sees.

	skip := plainidhttp.WithSkip(func(r *http.Request) bool {
		return r.URL.Path == "/healthz"
	})

	authorize, err := plainidhttp.Middleware(cfg, skip)
	if err != nil {
		log.Fatalf("plainid middleware: %v", err)
	}
	logger := requestLogger(cfg.Logger)

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// SetURL keeps the inbound path and query as-is under the
			// upstream's host: the request the PDP judged is the request the
			// upstream receives.
			pr.SetURL(upstream)
			pr.Out.Host = pr.In.Host
			// SetXForwarded appends the caller's address and sets
			// X-Forwarded-Proto/Host for the upstream.
			pr.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// An upstream failure is not an authorization failure; keep them
			// distinguishable in the logs and answer 502.
			slog.Error("upstream error", "path", r.URL.Path,
				"requestId", r.Header.Get(plainid.RequestIDHeader), "error", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
		Transport: upstreamTransport(),
	}

	mux := http.NewServeMux()

	// Liveness is answered here rather than proxied, and is left out of the
	// logger chain because health checks are high-frequency noise. It still
	// passes through authorize, where cfg.Skip is what lets it by — so
	// exclusions stay declared in one place instead of being implied by
	// routing.
	mux.Handle("/healthz", authorize(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("ok"))
		})))
	// The chain runs outermost first: logger, then authorize, then the proxy.
	//
	//	request ──▶ logger ──▶ authorize ──▶ proxy ──▶ upstream
	//	           │           │
	//	           │           └─ 403 on anything but PERMIT
	//	           └─ logs either outcome, with the status and duration
	//
	// Order matters. The logger wraps the authorizer so that denials are
	// logged too; swapped around, it would only ever see permitted traffic —
	// exactly the requests you least need a record of.
	mux.Handle("/", chain(proxy, logger, authorize))

	srv := &http.Server{
		Addr:              env("LISTEN_ADDR", ":8080"),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("proxying %s → %s, authorizing against %s", srv.Addr, upstream, cfg.URL)
	log.Fatal(srv.ListenAndServe())
}

// upstreamTransport pools connections to the upstream, the same way the
// library pools its connections to the PDP.
func upstreamTransport() http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 64
	t.IdleConnTimeout = 90 * time.Second
	t.ResponseHeaderTimeout = 30 * time.Second
	return t
}

// chain composes middleware so that the first argument is the outermost
// wrapper: chain(h, a, b) serves a(b(h)). Reading the call left to right gives
// the order a request passes through them.
func chain(h http.Handler, middleware ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return h
}

// requestLogger logs one line per request with the method, path, status and
// duration. Placed outside the PlainID middleware it records denials as well,
// and shares their request id — which is how a log line here is tied to the
// decision recorded in the PDP's audit trail.
func requestLogger(l *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started := time.Now()
			rec := &recorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			// Read the request id after the fact: on a permitted request the
			// PlainID middleware has normalized or generated it by now.
			l.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"bytes", rec.written,
				"duration", time.Since(started).Round(time.Microsecond),
				"requestId", r.Header.Get(plainid.RequestIDHeader),
				"authorized", r.Header.Get(plainid.AuthorizedByHeader) != "",
			)
		})
	}
}

// recorder captures the status code and response size for the log line.
//
// Wrapping a ResponseWriter in front of a reverse proxy means keeping the
// interfaces the proxy relies on: Flush for streaming and SSE, Hijack for
// connection upgrades such as websockets. Unwrap keeps http.ResponseController
// working for anything else.
type recorder struct {
	http.ResponseWriter
	status  int
	written int64
	wrote   bool
}

func (rec *recorder) WriteHeader(status int) {
	if !rec.wrote {
		rec.status, rec.wrote = status, true
		rec.ResponseWriter.WriteHeader(status)
	}
}

func (rec *recorder) Write(b []byte) (int, error) {
	rec.wrote = true
	n, err := rec.ResponseWriter.Write(b)
	rec.written += int64(n)
	return n, err
}

func (rec *recorder) Unwrap() http.ResponseWriter { return rec.ResponseWriter }

func (rec *recorder) Flush() {
	if f, ok := rec.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rec *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rec.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("reverse-proxy: the underlying ResponseWriter cannot be hijacked")
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
