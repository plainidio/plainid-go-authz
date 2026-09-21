package plainid

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// v3Stub answers the permit-deny v3 endpoint with a canned response and keeps
// the last payload it was sent.
type v3Stub struct {
	*httptest.Server
	status  int
	body    string
	delay   time.Duration
	calls   int
	lastReq *http.Request
	lastRaw []byte
}

func newV3Stub(t *testing.T, path string) *v3Stub {
	t.Helper()
	s := &v3Stub{status: http.StatusOK, body: `{"data":{"result":"PERMIT"}}`}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			t.Errorf("PDP called at %q, want %q", r.URL.Path, path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("PDP called with %s, want POST — identity data does not belong in a URL", r.Method)
		}
		s.calls++
		s.lastRaw, _ = io.ReadAll(r.Body)
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

func (s *v3Stub) payload(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(s.lastRaw, &m); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	return m
}

func v3Client(t *testing.T, url string, tweak func(*Config)) *Client {
	t.Helper()
	cfg := Config{
		URL:          url,
		ClientID:     "cid",
		ClientSecret: "shh",
		AuthMethod:   AuthMethodSecret,
		EntityTypeID: "Application_Users",
		Logger:       quietLogger(),
	}
	if tweak != nil {
		tweak(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

var testUser = Identity{
	ID:         "angela_bell",
	Attributes: map[string][]string{"region": {"US"}},
}

func TestCanPermits(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	c := v3Client(t, pdp.URL, nil)

	ok := c.Can(context.Background(), testUser, "Read", Resource{
		Type:       "Accounts",
		Path:       "AS-12",
		Attributes: map[string][]string{"branch": {"San Jose"}},
	})
	if !ok {
		t.Fatal("Can = false, want true")
	}

	p := pdp.payload(t)
	if p["entityId"] != "angela_bell" || p["entityTypeId"] != "Application_Users" {
		t.Errorf("identity mapping wrong: %v", p)
	}
	// Attribute values are arrays, always. A bare string does not error — it
	// silently fails to match, which is the most expensive bug in this API.
	attrs := p["entityAttributes"].(map[string]any)
	if _, ok := attrs["region"].([]any); !ok {
		t.Errorf("entityAttributes.region = %#v, want an array", attrs["region"])
	}
	groups := p["listOfResources"].([]any)
	if len(groups) != 1 {
		t.Fatalf("listOfResources = %v", groups)
	}
	g := groups[0].(map[string]any)
	if g["resourceType"] != "Accounts" {
		t.Errorf("resourceType = %v", g["resourceType"])
	}
	res := g["resources"].([]any)[0].(map[string]any)
	if res["action"] != "Read" || res["path"] != "AS-12" {
		t.Errorf("resource entry = %v", res)
	}
	if _, ok := res["assetAttributes"].(map[string]any)["branch"].([]any); !ok {
		t.Errorf("assetAttributes.branch must be an array, got %#v", res["assetAttributes"])
	}
	if p["useCache"] != true {
		t.Errorf("useCache = %v, want true by default", p["useCache"])
	}
	// The Scope authenticates itself; the end user travels in the payload.
	if got := pdp.lastReq.Header.Get("X-Client-Id"); got != "cid" {
		t.Errorf("X-Client-Id = %q", got)
	}
	if got := pdp.lastReq.Header.Get("X-Client-Secret"); got != "shh" {
		t.Errorf("X-Client-Secret = %q", got)
	}
	if pdp.lastReq.Header.Get("X-Request-ID") == "" {
		t.Error("X-Request-ID must be sent: it is what ties this to the PDP audit record")
	}
}

func TestCheckGroupsResourcesByType(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	c := v3Client(t, pdp.URL, nil)

	c.Check(context.Background(), Query{
		Identity: testUser,
		Resources: []Resource{
			{Type: "Accounts", Action: "Read", Path: "A1"},
			{Type: "Orders", Action: "Read", Prefetch: true},
			{Type: "Accounts", Action: "Delete", Path: "A2"},
		},
	})
	if pdp.calls != 1 {
		t.Fatalf("PDP called %d times, want 1 — a batch must not become a loop", pdp.calls)
	}
	groups := pdp.payload(t)["listOfResources"].([]any)
	if len(groups) != 2 {
		t.Fatalf("want 2 resource-type groups, got %d: %v", len(groups), groups)
	}
	first := groups[0].(map[string]any)
	if first["resourceType"] != "Accounts" || len(first["resources"].([]any)) != 2 {
		t.Errorf("Accounts group = %v", first)
	}
	if second := groups[1].(map[string]any); second["prefetch"] != true {
		t.Errorf("Orders group lost prefetch: %v", second)
	}
}

func TestCheckReadsDetails(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	pdp.body = `{"data":{"result":"PERMIT","response":[{
		"allowed":[{"path":"AS-12","action":"Read","template":"Accounts"}],
		"denied":[],"not_applicable":[]}]}}`
	c := v3Client(t, pdp.URL, func(cfg *Config) { cfg.IncludeDetails = true })

	d := c.Check(context.Background(), Ask(testUser, "Read", Resource{Type: "Accounts", Path: "AS-12"}))
	if !d.Permit {
		t.Fatalf("Permit = false: %+v", d)
	}
	if pdp.payload(t)["includeDetails"] != true {
		t.Error("includeDetails was not sent")
	}
	if !d.Allows("accounts", "read", "AS-12") {
		t.Errorf("Allows = false, Allowed = %+v", d.Allowed)
	}
	if d.Allows("Accounts", "Delete", "") {
		t.Error("Allows must not match an action that was not allowed")
	}
}

func TestCheckDistinguishesNoPolicyFromDenial(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	pdp.body = `{"data":{"result":"DENY","response":[{
		"allowed":[],"denied":[],
		"not_applicable":[{"path":"AS-12","action":"Read","template":"Accounts"}]}]}}`
	c := v3Client(t, pdp.URL, func(cfg *Config) { cfg.IncludeDetails = true })

	d := c.Check(context.Background(), Ask(testUser, "Read", Resource{Type: "Accounts", Path: "AS-12"}))
	if d.Permit {
		t.Fatal("not_applicable must not permit")
	}
	if !d.NoPolicyMatched() {
		t.Error("NoPolicyMatched = false: a modelling gap reads as a denial and gets debugged as a code bug")
	}
	if !d.DeniedByPolicy() || d.Failed() {
		t.Errorf("a real verdict must not look like a PDP failure: %+v", d)
	}
}

// Every one of these is a refusal. These tests are the security of the
// library, so they are written as deliberately as the happy path.
func TestCheckFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		failure bool // refused because the PDP did not answer, not by policy
	}{
		{"deny", 200, `{"data":{"result":"DENY"}}`, false},
		{"unexpected result", 200, `{"data":{"result":"MAYBE"}}`, false},
		{"missing result", 200, `{"data":{}}`, false},
		{"empty object", 200, `{}`, false},
		{"unparseable", 200, `not json`, true},
		{"token-shaped answer", 200, `{"response":[{"access":[]}]}`, false},
		{"unauthorized", 401, `{"error":"bad credentials"}`, true},
		{"server error", 500, `oops`, true},
		{"identity template error", 400, `{"errorCode":"RT-087"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pdp := newV3Stub(t, permitDenyPath)
			pdp.status, pdp.body = tc.status, tc.body
			c := v3Client(t, pdp.URL, nil)

			d := c.Check(context.Background(), Ask(testUser, "Read", Resource{Type: "Accounts"}))
			if d.Permit {
				t.Fatalf("Permit = true for %s — this must fail closed", tc.name)
			}
			if d.Reason == "" {
				t.Error("a refusal with no reason cannot be operated")
			}
			if d.Failed() != tc.failure {
				t.Errorf("Failed() = %v, want %v (policy denial and PDP outage must stay distinguishable)", d.Failed(), tc.failure)
			}
			if tc.failure && !errors.Is(d.Err, ErrPDPUnavailable) {
				t.Errorf("Err does not wrap ErrPDPUnavailable: %v", d.Err)
			}
		})
	}
}

func TestCheckDeniesWhenPDPIsUnreachable(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	url := pdp.URL
	pdp.Close()

	c := v3Client(t, url, func(cfg *Config) { cfg.RequestTimeout = time.Second })
	d := c.Check(context.Background(), Ask(testUser, "Read", Resource{Type: "Accounts"}))
	if d.Permit || !d.Failed() {
		t.Fatalf("an unreachable PDP must deny and be recorded as a failure: %+v", d)
	}
}

func TestCheckDeniesOnTimeout(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	pdp.delay = 200 * time.Millisecond
	c := v3Client(t, pdp.URL, func(cfg *Config) { cfg.RequestTimeout = 20 * time.Millisecond })

	if d := c.Check(context.Background(), Ask(testUser, "Read", Resource{Type: "Accounts"})); d.Permit {
		t.Fatal("a timeout must deny")
	}
	if pdp.calls > 1 {
		t.Errorf("PDP called %d times — retrying a timeout multiplies a slow call", pdp.calls)
	}
}

func TestCheckRejectsIncompleteQueries(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	c := v3Client(t, pdp.URL, nil)

	cases := map[string]Query{
		"no identity":  {Resources: []Resource{{Type: "Accounts", Action: "Read"}}},
		"no resources": {Identity: testUser},
		"no type":      Ask(testUser, "Read", Resource{}),
		"no action":    {Identity: testUser, Resources: []Resource{{Type: "Accounts"}}},
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			if d := c.Check(context.Background(), q); d.Permit {
				t.Fatal("an incomplete query must not permit")
			}
		})
	}
	if pdp.calls != 0 {
		t.Errorf("PDP called %d times for queries that never should have been sent", pdp.calls)
	}
}

func TestEntityTypeIDIsRequiredSomewhere(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	c := v3Client(t, pdp.URL, func(cfg *Config) { cfg.EntityTypeID = "" })

	if d := c.Check(context.Background(), Ask(testUser, "Read", Resource{Type: "Accounts"})); d.Permit {
		t.Fatal("no entityTypeId anywhere must not permit")
	}
	// Per call, it overrides an empty configuration.
	q := Ask(Identity{ID: "u", TypeID: "Employees"}, "Read", Resource{Type: "Accounts"})
	if d := c.Check(context.Background(), q); !d.Permit {
		t.Fatalf("per-call TypeID was not used: %+v", d)
	}
	if got := pdp.payload(t)["entityTypeId"]; got != "Employees" {
		t.Errorf("entityTypeId = %v", got)
	}
}

func TestPerCallBearerTokenOverridesCredentials(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	c := v3Client(t, pdp.URL, nil)

	q := Ask(testUser, "Read", Resource{Type: "Accounts"})
	q.BearerToken = "abc123"
	q.UseCache = Bool(false)
	c.Check(context.Background(), q)

	if got := pdp.lastReq.Header.Get("Authorization"); got != "Bearer abc123" {
		t.Errorf("Authorization = %q", got)
	}
	if pdp.lastReq.Header.Get("X-Client-Secret") != "" {
		t.Error("the secret must not be sent alongside a per-call bearer token")
	}
	if pdp.payload(t)["useCache"] != false {
		t.Error("per-call UseCache override was ignored")
	}
}

func TestTracingRedactsCredentials(t *testing.T) {
	logged := redact([]byte(`{"clientSecret":"shh","headers":{"authorization":["Bearer x"]},"entityId":"u"}`))
	var m map[string]any
	if err := json.Unmarshal(logged, &m); err != nil {
		t.Fatalf("redacted payload is not JSON: %v", err)
	}
	if m["clientSecret"] != "<redacted>" {
		t.Errorf("clientSecret = %v", m["clientSecret"])
	}
	if h := m["headers"].(map[string]any); h["authorization"] != "<redacted>" {
		t.Errorf("nested authorization = %v", h["authorization"])
	}
	if m["entityId"] != "u" {
		t.Error("redaction must not eat the fields you are debugging")
	}
}
