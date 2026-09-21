package plainid

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// pdpStub records the last decision call and answers with a canned response.
type pdpStub struct {
	*httptest.Server
	status  int
	body    string
	delay   time.Duration
	lastReq *http.Request
	lastPay Payload
}

func newPDPStub(t *testing.T) *pdpStub {
	t.Helper()
	s := &pdpStub{status: http.StatusOK, body: `{"data":{"result":"PERMIT"}}`}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != decisionPath {
			t.Errorf("PDP called at %q, want %q", r.URL.Path, decisionPath)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &s.lastPay)
		s.lastReq = r.Clone(context.Background())
		if s.delay > 0 {
			time.Sleep(s.delay)
		}
		w.WriteHeader(s.status)
		_, _ = io.WriteString(w, s.body)
	}))
	t.Cleanup(s.Close)
	return s
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// decide authorizes a neutral request, the way any framework adapter does.
func decide(t *testing.T, cfg Config, req Request) Decision {
	t.Helper()
	cfg.Logger = quietLogger()
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a.AuthorizeRequest(context.Background(), req)
}

// get builds a plain GET request for the tests below.
func get(path string, header map[string][]string) Request {
	return Request{
		Method:     http.MethodGet,
		Path:       path,
		Scheme:     "https",
		RemoteAddr: "203.0.113.7:4321",
		Header:     header,
	}
}

func TestAuthorizePermit(t *testing.T) {
	pdp := newPDPStub(t)
	req := get("/api/v1/orders", map[string][]string{
		"Authorization": {"Bearer caller-token"},
		"X-Request-ID":  {"given-id"},
	})

	d := decide(t, Config{URL: pdp.URL, ClientID: "cid"}, req)

	if !d.Permit || d.Result != "PERMIT" {
		t.Fatalf("decision = %+v, want permit", d)
	}
	if d.RequestID != "given-id" {
		t.Errorf("requestId = %q, want the caller's", d.RequestID)
	}
	if got := pdp.lastReq.Header.Get("X-Client-Id"); got != "cid" {
		t.Errorf("X-Client-Id = %q", got)
	}
	if got := pdp.lastReq.Header.Get("Authorization"); got != "Bearer caller-token" {
		t.Errorf("token mode must forward the caller's Authorization, got %q", got)
	}
	if got := pdp.lastReq.Header.Get("X-Request-ID"); got != "given-id" {
		t.Errorf("X-Request-ID = %q", got)
	}
	if got := pdp.lastPay.URI.Path[0]; got != "/api/v1/orders" {
		t.Errorf("payload path[0] = %q", got)
	}
}

func TestAuthorizeSecretMode(t *testing.T) {
	pdp := newPDPStub(t)
	req := get("/x", map[string][]string{"Authorization": {"Bearer caller-token"}})

	cfg := Config{
		URL: pdp.URL, ClientID: "cid", ClientSecret: "shh",
		AuthMethod: AuthMethodSecret,
	}
	if d := decide(t, cfg, req); !d.Permit {
		t.Fatalf("decision = %+v, want permit", d)
	}
	if got := pdp.lastReq.Header.Get("X-Client-Secret"); got != "shh" {
		t.Errorf("X-Client-Secret = %q", got)
	}
	if got := pdp.lastReq.Header.Get("Authorization"); got != "" {
		t.Errorf("secret mode must not forward the caller's Authorization, got %q", got)
	}
	if got := pdp.lastPay.Headers["authorization"]; len(got) != 1 {
		t.Errorf("the caller's identity must still reach the PDP in the payload, got %#v", got)
	}
	if pdp.lastPay.AuthenticationMethod != AuthMethodSecret {
		t.Errorf("authenticationMethod = %q", pdp.lastPay.AuthenticationMethod)
	}
}

func TestAuthorizeCustomCredentialHeaders(t *testing.T) {
	pdp := newPDPStub(t)
	cfg := Config{
		URL: pdp.URL, ClientID: "cid", ClientSecret: "shh", AuthMethod: AuthMethodSecret,
		ClientIDHeader: "x-plainid-client-id", ClientSecretHeader: "x-plainid-client-secret",
	}
	decide(t, cfg, get("/x", nil))

	if got := pdp.lastReq.Header.Get("x-plainid-client-id"); got != "cid" {
		t.Errorf("custom client id header = %q", got)
	}
	if got := pdp.lastReq.Header.Get("X-Client-Id"); got != "" {
		t.Errorf("default header should not also be sent, got %q", got)
	}
}

func TestAuthorizeForwardsConfiguredHeaders(t *testing.T) {
	pdp := newPDPStub(t)
	req := get("/x", map[string][]string{
		"X-Tenant": {"acme"},
		"X-Other":  {"ignored"},
	})

	cfg := Config{URL: pdp.URL, HeadersToForward: []string{"X-Tenant"}}
	decide(t, cfg, req)

	if got := pdp.lastReq.Header.Get("X-Tenant"); got != "acme" {
		t.Errorf("X-Tenant = %q", got)
	}
	if got := pdp.lastReq.Header.Get("X-Other"); got != "" {
		t.Errorf("unlisted headers must not be copied onto the PDP call, got %q", got)
	}
}

// Every one of these must fail closed.
func TestAuthorizeFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"policy deny", 200, `{"data":{"result":"DENY"}}`},
		{"lowercase permit is not PERMIT", 200, `{"data":{"result":"permit"}}`},
		{"missing result", 200, `{"data":{}}`},
		{"empty object", 200, `{}`},
		{"unparseable", 200, `<html>not json</html>`},
		{"mcp-shaped answer", 200, `{"data":{"data":[{"output":{"accessResponse":{"result":"PERMIT"}}}]}}`},
		{"unauthorized", 401, `{"error":"bad credentials"}`},
		{"server error", 500, `boom`},
		{"identity template error", 200, `{"errors":[{"code":"RT-087"}]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pdp := newPDPStub(t)
			pdp.status, pdp.body = c.status, c.body

			d := decide(t, Config{URL: pdp.URL}, get("/x", nil))
			if d.Permit {
				t.Fatalf("decision = %+v, want denied", d)
			}
			if d.Reason == "" {
				t.Error("a denial must carry a reason for the logs")
			}
		})
	}
}

func TestAuthorizeDeniesWhenPDPUnreachable(t *testing.T) {
	pdp := newPDPStub(t)
	url := pdp.URL
	pdp.Close()

	d := decide(t, Config{URL: url}, get("/x", nil))
	if d.Permit {
		t.Fatalf("decision = %+v, want denied", d)
	}
	if d.Err == nil {
		t.Error("an outage must be recorded as an error")
	}
}

func TestAuthorizeDeniesOnTimeout(t *testing.T) {
	pdp := newPDPStub(t)
	pdp.delay = 200 * time.Millisecond

	cfg := Config{URL: pdp.URL, RequestTimeout: 20 * time.Millisecond}
	if d := decide(t, cfg, get("/x", nil)); d.Permit {
		t.Fatalf("decision = %+v, want denied", d)
	}
}

func TestAuthorizeDeniesOversizedBody(t *testing.T) {
	pdp := newPDPStub(t)
	req := get("/x", nil)
	req.Method, req.Body = "POST", []byte(strings.Repeat("x", 32))

	d := decide(t, Config{URL: pdp.URL, MaxBodyBytes: 16}, req)
	if d.Permit {
		t.Fatalf("decision = %+v, want denied", d)
	}
	if pdp.lastReq != nil {
		t.Error("an oversized body must be denied without calling the PDP")
	}
}

func TestDecideUsesOneCallPerRequest(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(500)
	}))
	defer srv.Close()

	decide(t, Config{URL: srv.URL}, get("/x", nil))
	if calls != 1 {
		t.Errorf("PDP called %d times, want exactly 1 — retries multiply a slow call", calls)
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("URL must be required")
	}
	if _, err := New(Config{URL: "u", AuthMethod: "basic"}); err == nil {
		t.Error("unknown auth method must be rejected")
	}
	if _, err := New(Config{URL: "u", AuthMethod: AuthMethodSecret}); err == nil {
		t.Error("secret mode without a secret must be rejected")
	}
	a, err := New(Config{URL: "https://pdp.example/api/"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.endpoints.decision != "https://pdp.example/api"+decisionPath {
		t.Errorf("endpoint = %q", a.endpoints.decision)
	}
	if c := a.Config(); c.RequestTimeout != DefaultRequestTimeout ||
		c.OnPreventStatusCode != DefaultOnPreventStatus || c.MaxBodyBytes != DefaultMaxBodyBytes {
		t.Errorf("defaults not applied: %+v", c)
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("PLAINID_URL", "https://pdp.example/api")
	t.Setenv("PLAINID_CLIENT_ID", "cid")
	t.Setenv("PLAINID_CLIENT_SECRET", "none") // the literal "none" means unset
	t.Setenv("PLAINID_AUTH_METHOD", "token")
	t.Setenv("PLAINID_REQUEST_TIMEOUT", "3")
	t.Setenv("PLAINID_HEADERS_TO_FORWARD", "X-Tenant, X-Region")
	t.Setenv("PLAINID_RUNTIME_FINE_TUNE", `{"k":"v"}`)
	t.Setenv("ON_PREVENT_STATUS_CODE", "401")
	t.Setenv("MAX_BODY_BYTES", "2048")
	t.Setenv("ENABLE_TRACING", "true")

	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if c.ClientSecret != "" {
		t.Errorf(`the literal "none" must read as unset, got %q`, c.ClientSecret)
	}
	if c.RequestTimeout != 3*time.Second || c.OnPreventStatusCode != 401 ||
		c.MaxBodyBytes != 2048 || !c.EnableTracing {
		t.Errorf("config = %+v", c)
	}
	if len(c.HeadersToForward) != 2 || c.HeadersToForward[1] != "X-Region" {
		t.Errorf("HeadersToForward = %#v", c.HeadersToForward)
	}
	if c.RuntimeFineTune["k"] != "v" {
		t.Errorf("RuntimeFineTune = %#v", c.RuntimeFineTune)
	}

	t.Setenv("PLAINID_REQUEST_TIMEOUT", "abc")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("an invalid timeout must be rejected at startup, not at request time")
	}
}
