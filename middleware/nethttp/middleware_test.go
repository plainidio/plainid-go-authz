package plainidhttp_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plainidio/plainid-go-authz/internal/authztest"
	"github.com/plainidio/plainid-go-authz/middleware/nethttp"
	"github.com/plainidio/plainid-go-authz/plainid"
)

const (
	permitAnswer = `{"data":{"result":"PERMIT"}}`
	denyAnswer   = `{"data":{"result":"DENY"}}`
)

// fixture is a gateway whose verdict is fixed, for the net/http-specific
// behaviour that has nothing to do with policy.
type fixture struct {
	pdp      *authztest.StubPDP
	backend  *authztest.Backend
	enforcer *plainidhttp.Enforcer
	handler  http.Handler
}

func newFixture(t *testing.T, answer string, opts ...plainidhttp.Option) *fixture {
	t.Helper()
	pdp := authztest.NewStubPDP(t)
	pdp.SetResponse(http.StatusOK, answer)
	backend := authztest.NewBackend()

	cfg := plainid.Config{
		URL:    pdp.URL(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	e, err := plainidhttp.New(cfg, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &fixture{pdp: pdp, backend: backend, enforcer: e, handler: e.Handler(backend.Handler())}
}

func (f *fixture) serve(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

func TestBodyIsReplayedToTheBackend(t *testing.T) {
	f := newFixture(t, permitAnswer)
	body := `{"amount":12.5}`

	f.serve(httptest.NewRequest("POST", "/api/v1/orders", strings.NewReader(body)))

	hit, ok := f.backend.Last()
	if !ok {
		t.Fatal("the backend was not reached")
	}
	if hit.Body != body {
		t.Errorf("backend body = %q, want %q", hit.Body, body)
	}
	// The PDP must have seen the same body.
	calls := f.pdp.Calls()
	if len(calls) != 1 {
		t.Fatalf("%d decision calls, want 1", len(calls))
	}
	sent, _ := calls[0].Payload["body"].(map[string]any)
	if sent["amount"] != 12.5 {
		t.Errorf("payload body = %#v, want the parsed JSON", calls[0].Payload["body"])
	}
}

func TestOversizedBodyIsDeniedWithoutCallingThePDP(t *testing.T) {
	pdp := authztest.NewStubPDP(t)
	pdp.SetResponse(http.StatusOK, permitAnswer)
	backend := authztest.NewBackend()

	cfg := plainid.Config{
		URL:          pdp.URL(),
		MaxBodyBytes: 16,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	e, err := plainidhttp.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/orders", strings.NewReader(strings.Repeat("x", 32)))
	e.Handler(backend.Handler()).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 — an uninspectable body is a denial", w.Code)
	}
	if len(backend.Hits()) != 0 {
		t.Error("the backend must not be reached")
	}
	if n := len(pdp.Calls()); n != 0 {
		t.Errorf("%d decision calls, want 0 — no point asking about a body we cannot send", n)
	}
}

func TestCallerRequestIDIsNotDuplicated(t *testing.T) {
	f := newFixture(t, permitAnswer)
	r := httptest.NewRequest("GET", "/api/v1/orders", nil)
	// Lower-cased, as a client may well send it.
	r.Header["x-request-id"] = []string{"caller-id"}

	f.serve(r)

	hit, ok := f.backend.Last()
	if !ok {
		t.Fatal("the backend was not reached")
	}
	var values []string
	for name, v := range hit.Header {
		if strings.EqualFold(name, "X-Request-ID") {
			values = append(values, v...)
		}
	}
	if len(values) != 1 || values[0] != "caller-id" {
		t.Errorf("request id headers = %#v, want exactly one \"caller-id\"", values)
	}
}

// An outer middleware — a logger, say — must be able to correlate a denial
// with the PDP audit record, so the request id is stamped whatever the verdict.
func TestRequestIDIsVisibleToOuterMiddlewareOnDenial(t *testing.T) {
	f := newFixture(t, denyAnswer)

	var seen string
	outer := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			seen = r.Header.Get(plainid.RequestIDHeader) // read after the inner handler
		})
	}

	r := httptest.NewRequest("GET", "/api/v1/orders", nil)
	w := httptest.NewRecorder()
	outer(f.handler).ServeHTTP(w, r)

	if seen == "" {
		t.Fatal("outer middleware cannot see a request id for a denied request")
	}
	if got := w.Header().Get(plainid.RequestIDHeader); got != seen {
		t.Errorf("logged id %q differs from the one echoed to the caller %q", seen, got)
	}
	if r.Header.Get(plainid.AuthorizedByHeader) != "" {
		t.Error("a denied request must not be stamped as authorized")
	}
}

func TestCustomDenialResponse(t *testing.T) {
	pdp := authztest.NewStubPDP(t)
	pdp.SetResponse(http.StatusOK, denyAnswer)
	cfg := plainid.Config{
		URL:                  pdp.URL(),
		OnPreventStatusCode:  401,
		OnPreventBody:        "nope",
		OnPreventContentType: "text/plain",
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	e, err := plainidhttp.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	w := httptest.NewRecorder()
	e.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))

	if w.Code != 401 || w.Body.String() != "nope" || w.Header().Get("Content-Type") != "text/plain" {
		t.Errorf("custom denial not applied: %d %q %q",
			w.Code, w.Body, w.Header().Get("Content-Type"))
	}
}

func TestSkipBypassesEnforcement(t *testing.T) {
	f := newFixture(t, denyAnswer, plainidhttp.WithSkip(
		func(r *http.Request) bool { return r.URL.Path == "/healthz" },
	))

	f.serve(httptest.NewRequest("GET", "/healthz", nil))
	if len(f.backend.Hits()) != 1 {
		t.Fatal("an excluded route must bypass enforcement")
	}
	if n := len(f.pdp.Calls()); n != 0 {
		t.Errorf("an excluded route must not call the PDP, got %d calls", n)
	}

	f.backend.Reset()
	f.serve(httptest.NewRequest("GET", "/api/v1/orders", nil))
	if len(f.backend.Hits()) != 0 {
		t.Error("the exclusion must not widen to other routes")
	}
}

func TestConstructorsValidateConfig(t *testing.T) {
	if _, err := plainidhttp.New(plainid.Config{}); err == nil {
		t.Error("New must reject a configuration with no URL")
	}
	if _, err := plainidhttp.Middleware(plainid.Config{}); err == nil {
		t.Error("Middleware must validate its configuration")
	}
	mw, err := plainidhttp.Middleware(plainid.Config{
		URL:    "https://pdp.example/api",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("Middleware: %v", err)
	}
	if mw(http.NotFoundHandler()) == nil {
		t.Error("Middleware must wrap a handler")
	}
}

// Authorize is the standalone path: it must behave exactly as Handler does,
// minus writing the response.
func TestAuthorizeStandalone(t *testing.T) {
	f := newFixture(t, permitAnswer)
	r := httptest.NewRequest("POST", "/api/v1/orders", strings.NewReader(`{"a":1}`))

	d := f.enforcer.Authorize(r)
	if !d.Permit {
		t.Fatalf("decision = %+v, want permit", d)
	}
	if r.Header.Get(plainid.RequestIDHeader) != d.RequestID {
		t.Error("Authorize must stamp the request id on the request")
	}
	if r.Header.Get(plainid.AuthorizedByHeader) != plainid.AuthorizedByValue {
		t.Error("Authorize must stamp X-Authorized-By on a permit")
	}
	body, _ := io.ReadAll(r.Body)
	if string(body) != `{"a":1}` {
		t.Errorf("body not restored for the caller to forward: %q", body)
	}

	// Nothing was written to the client; that is the caller's job.
	f.pdp.SetResponse(http.StatusOK, denyAnswer)
	w := httptest.NewRecorder()
	d = f.enforcer.Authorize(httptest.NewRequest("GET", "/api/v1/orders", nil))
	if d.Permit {
		t.Fatal("decision = permit, want denied")
	}
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Error("Authorize must not write a response")
	}
	f.enforcer.WriteDenial(w, d.RequestID)
	if w.Code != http.StatusForbidden || w.Header().Get(plainid.RequestIDHeader) != d.RequestID {
		t.Errorf("WriteDenial wrote %d with id %q", w.Code, w.Header().Get(plainid.RequestIDHeader))
	}
}

// The adapter must expose the core authorizer, so callers can enforce outside
// a handler chain.
func TestAuthorizerIsReachable(t *testing.T) {
	f := newFixture(t, permitAnswer)
	if f.enforcer.Authorizer() == nil {
		t.Fatal("Authorizer() returned nil")
	}
	if got := f.enforcer.Authorizer().Denial().StatusCode; got != http.StatusForbidden {
		t.Errorf("denial status = %d, want 403", got)
	}
}
