package plainid

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func testAuthorizer(t *testing.T, cfg Config) *Authorizer {
	t.Helper()
	if cfg.URL == "" {
		cfg.URL = "https://pdp.example/api"
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestBuildPathShape(t *testing.T) {
	cases := []struct {
		path string
		want []string
	}{
		// The full path at index 0, then the segments — with no empty entry
		// for the leading slash, so segment N sits at index N.
		{"/api/v1/orders/42", []string{"/api/v1/orders/42", "api", "v1", "orders", "42"}},
		{"/orders", []string{"/orders", "orders"}},
		{"/", []string{"/", ""}},
		{"", []string{"/", ""}},
		{"/orders/", []string{"/orders/", "orders", ""}},
	}
	for _, c := range cases {
		if got := buildPath(c.path); !reflect.DeepEqual(got, c.want) {
			t.Errorf("buildPath(%q) = %#v, want %#v", c.path, got, c.want)
		}
	}
}

func TestBuildPayload(t *testing.T) {
	a := testAuthorizer(t, Config{})
	req := Request{
		Method:     "post",
		Path:       "/api/v1/orders/42",
		Query:      map[string]string{"expand": "items", "page": "2"},
		Scheme:     "http",
		RemoteAddr: "203.0.113.7:54321",
		Header: map[string][]string{
			"Authorization": {"Bearer abc"},
			"X-Tenant":      {"acme"},
			"Accept":        {"application/json, text/plain"},
			"X-Empty":       {""},
		},
		Body: []byte(`{"amount":12.5}`),
	}

	p := a.BuildPayload(req, "req-1")

	if p.Method != "POST" {
		t.Errorf("method = %q, want POST (uppercased)", p.Method)
	}
	if p.IPAddress != "203.0.113.7" {
		t.Errorf("ipAddress = %q", p.IPAddress)
	}
	if p.URI.Schema != "http" {
		t.Errorf("schema = %q", p.URI.Schema)
	}
	if want := map[string]string{"expand": "items", "page": "2"}; !reflect.DeepEqual(p.URI.Query, want) {
		t.Errorf("query = %#v, want %#v", p.URI.Query, want)
	}
	if got := p.Headers["x-tenant"]; !reflect.DeepEqual(got, []string{"acme"}) {
		t.Errorf("headers[x-tenant] = %#v", got)
	}
	if got := p.Headers["accept"]; !reflect.DeepEqual(got, []string{"application/json", "text/plain"}) {
		t.Errorf("accept should split on commas, got %#v", got)
	}
	if _, ok := p.Headers["x-empty"]; ok {
		t.Error("empty headers must be omitted")
	}
	if p.AuthenticationMethod != AuthMethodToken {
		t.Errorf("authenticationMethod = %q", p.AuthenticationMethod)
	}
	body, ok := p.Body.(map[string]any)
	if !ok || body["amount"] != 12.5 {
		t.Errorf("body = %#v, want parsed JSON", p.Body)
	}

	// meta.runtimeFineTune and uri.query must serialize as {} rather than null.
	encoded, _ := json.Marshal(p)
	for _, want := range []string{`"runtimeFineTune":{}`, `"path":["/api/v1/orders/42"`} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("payload missing %s: %s", want, encoded)
		}
	}
}

func TestBuildPayloadEmptyQuerySerializesAsObject(t *testing.T) {
	a := testAuthorizer(t, Config{})
	p := a.BuildPayload(Request{Method: "GET", Path: "/x"}, "id")

	if encoded, _ := json.Marshal(p); !strings.Contains(string(encoded), `"query":{}`) {
		t.Errorf("empty query must serialize as {}, got %s", encoded)
	}
}

func TestBuildPayloadNonJSONBodyIsSentAsString(t *testing.T) {
	a := testAuthorizer(t, Config{})
	p := a.BuildPayload(Request{Method: "POST", Path: "/x", Body: []byte("not json at all")}, "id")

	if p.Body != "not json at all" {
		t.Errorf("body = %#v, want the raw string — an unparseable body is not a denial", p.Body)
	}
}

func TestBuildPayloadEmptyBodyOmitted(t *testing.T) {
	a := testAuthorizer(t, Config{})
	p := a.BuildPayload(Request{Method: "GET", Path: "/x"}, "id")

	if p.Body != nil {
		t.Errorf("body = %#v, want omitted", p.Body)
	}
	if encoded, _ := json.Marshal(p); strings.Contains(string(encoded), `"body"`) {
		t.Errorf("body key should be absent: %s", encoded)
	}
}

func TestReadCappedBody(t *testing.T) {
	if _, err := ReadCappedBody(strings.NewReader(strings.Repeat("x", 9)), 8); err != ErrBodyTooLarge {
		t.Errorf("err = %v, want ErrBodyTooLarge", err)
	}
	got, err := ReadCappedBody(strings.NewReader(strings.Repeat("x", 8)), 8)
	if err != nil {
		t.Fatalf("a body exactly at the limit must be allowed through: %v", err)
	}
	if len(got) != 8 {
		t.Errorf("read %d bytes, want 8", len(got))
	}
	if got, err := ReadCappedBody(nil, 8); err != nil || got != nil {
		t.Errorf("a nil body must read as empty, got %q %v", got, err)
	}
}

func TestForwardedHeadersAreOptIn(t *testing.T) {
	req := Request{
		Method:     "GET",
		Path:       "/x",
		Scheme:     "http",
		RemoteAddr: "10.0.0.1:1234",
		Header: map[string][]string{
			"X-Forwarded-For":   {"203.0.113.7, 10.0.0.2"},
			"X-Forwarded-Proto": {"https"},
		},
	}

	p := testAuthorizer(t, Config{}).BuildPayload(req, "id")
	if p.IPAddress != "10.0.0.1" || p.URI.Schema != "http" {
		t.Errorf("untrusted proxy headers must be ignored: ip=%q schema=%q", p.IPAddress, p.URI.Schema)
	}

	p = testAuthorizer(t, Config{TrustForwardedHeaders: true}).BuildPayload(req, "id")
	if p.IPAddress != "203.0.113.7" || p.URI.Schema != "https" {
		t.Errorf("trusted proxy headers must be resolved: ip=%q schema=%q", p.IPAddress, p.URI.Schema)
	}
}

func TestRequestIDIsCaseInsensitiveAndGenerated(t *testing.T) {
	a := testAuthorizer(t, Config{})

	if got := a.RequestID(map[string][]string{"x-request-id": {"caller-id"}}); got != "caller-id" {
		t.Errorf("RequestID = %q, want the caller's, whatever its casing", got)
	}
	generated := a.RequestID(nil)
	if len(generated) != 36 || generated[14] != '4' {
		t.Errorf("RequestID() = %q, want a generated v4 UUID", generated)
	}
	if generated == a.RequestID(nil) {
		t.Error("generated request ids must be unique")
	}
}
