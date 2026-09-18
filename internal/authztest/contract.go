package authztest

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Gateway is the system under test: a running server that enforces with the
// adapter being checked, in front of Backend, deciding against PDP.
type Gateway struct {
	// URL is the gateway's base URL.
	URL string
	// PDP and Backend are the ones the gateway was wired to.
	PDP     *StubPDP
	Backend *Backend
	// Denial is the refusal the gateway is configured to return.
	Denial DenialSpec
	// UnenforcedPath, if set, is a route the gateway deliberately excludes
	// (a health check). It is exercised to confirm the exclusion works and
	// has not widened.
	UnenforcedPath string
}

// DenialSpec is the expected refusal response.
type DenialSpec struct {
	StatusCode   int
	ContentType  string
	BodyContains string
}

// DefaultDenial is the contract's default refusal.
var DefaultDenial = DenialSpec{
	StatusCode:   http.StatusForbidden,
	ContentType:  "application/json",
	BodyContains: "Forbidden",
}

// RunContract drives the gateway from outside and checks the enforcement
// contract every adapter must satisfy. Adapters call this from their own test
// package; failures name the behaviour rather than the implementation, so the
// same suite reads correctly for any framework.
func RunContract(t *testing.T, gw Gateway) {
	t.Helper()
	if gw.Denial == (DenialSpec{}) {
		gw.Denial = DefaultDenial
	}

	t.Run("verdicts follow identity, method and path", func(t *testing.T) {
		cases := []struct {
			token, method, path string
			permit              bool
		}{
			{Admin, "GET", "/api/v1/orders", true},
			{Admin, "DELETE", "/api/v1/orders/42", true},
			{Reader, "GET", "/api/v1/orders", true},
			// Same path, different method: the method reaches the PDP.
			{Reader, "DELETE", "/api/v1/orders/42", false},
			// Same method, different path: the path array reaches the PDP.
			{Reader, "GET", "/api/v1/admin/users", false},
			{Anonymous, "GET", "/api/v1/orders", false},
		}
		for _, c := range cases {
			name := fmt.Sprintf("%s %s %s", identity(c.token), c.method, c.path)
			t.Run(name, func(t *testing.T) {
				gw.Backend.Reset()
				resp := call(t, gw.URL, c.method, c.path, c.token, nil)

				if c.permit {
					if resp.status != http.StatusOK {
						t.Fatalf("status = %d, want the backend's 200", resp.status)
					}
					if len(gw.Backend.Hits()) != 1 {
						t.Fatal("a permitted request must reach the backend")
					}
					return
				}
				if resp.status != gw.Denial.StatusCode {
					t.Fatalf("status = %d, want %d", resp.status, gw.Denial.StatusCode)
				}
				if len(gw.Backend.Hits()) != 0 {
					t.Fatal("a denied request must never reach the backend")
				}
			})
		}
	})

	t.Run("permitted requests reach the backend unmodified", func(t *testing.T) {
		gw.Backend.Reset()
		body := `{"amount":12.5}`
		resp := call(t, gw.URL, "POST", "/api/v1/orders?expand=items", Admin,
			map[string]string{"X-Custom": "kept", "Content-Type": "application/json"}, body)
		if resp.status != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.status)
		}

		hit, ok := gw.Backend.Last()
		if !ok {
			t.Fatal("the backend was not reached")
		}
		if hit.Method != "POST" || hit.Path != "/api/v1/orders" || hit.Query != "expand=items" {
			t.Errorf("method/path/query altered: %s %s?%s", hit.Method, hit.Path, hit.Query)
		}
		if hit.Body != body {
			t.Errorf("body = %q, want %q — the body must survive being inspected", hit.Body, body)
		}
		if hit.Header.Get("X-Custom") != "kept" {
			t.Error("the caller's headers must pass through")
		}
		if got := hit.Header.Get("X-Authorized-By"); got != "PlainID" {
			t.Errorf("X-Authorized-By = %q, want PlainID", got)
		}
		if hit.Header.Get("X-Request-ID") == "" {
			t.Error("the backend must receive a request id")
		}
	})

	t.Run("the denial is the configured response", func(t *testing.T) {
		resp := call(t, gw.URL, "GET", "/api/v1/admin/users", Reader, nil)

		if resp.status != gw.Denial.StatusCode {
			t.Errorf("status = %d, want %d", resp.status, gw.Denial.StatusCode)
		}
		if ct := resp.header.Get("Content-Type"); !strings.HasPrefix(ct, gw.Denial.ContentType) {
			t.Errorf("content-type = %q, want %q", ct, gw.Denial.ContentType)
		}
		if !strings.Contains(resp.body, gw.Denial.BodyContains) {
			t.Errorf("body = %q, want it to contain %q", resp.body, gw.Denial.BodyContains)
		}
		// Nothing about the policy, the PDP or the backend may leak.
		for _, leak := range []string{"PDP", "plainid", "DENY", "policy", "upstream", "runtime"} {
			if strings.Contains(strings.ToLower(resp.body), strings.ToLower(leak)) {
				t.Errorf("denial body leaks %q: %s", leak, resp.body)
			}
		}
	})

	t.Run("refusals are indistinguishable", func(t *testing.T) {
		// A policy denial, a PDP error and an unparseable answer must look
		// identical from outside; only the logs may tell them apart.
		var seen []string
		record := func(label string) {
			gw.Backend.Reset()
			resp := call(t, gw.URL, "GET", "/api/v1/orders", Admin, nil)
			seen = append(seen, fmt.Sprintf("%d|%s|%s",
				resp.status, resp.header.Get("Content-Type"), resp.body))
			if len(gw.Backend.Hits()) != 0 {
				t.Fatalf("%s: the backend must not be reached", label)
			}
		}

		gw.PDP.SetResponse(http.StatusOK, `{"data":{"result":"DENY"}}`)
		record("policy denial")
		gw.PDP.SetResponse(http.StatusInternalServerError, `internal detail that must not leak`)
		record("PDP error")
		gw.PDP.SetResponse(http.StatusOK, `<html>not json</html>`)
		record("unparseable answer")
		gw.PDP.SetResponse(http.StatusOK, `{"data":{}}`)
		record("missing result")
		gw.PDP.SetResponse(http.StatusOK, `{"data":{"result":"permit"}}`)
		record("wrong-case result")
		gw.PDP.ClearResponse()

		for i, got := range seen[1:] {
			if got != seen[0] {
				t.Errorf("refusal %d differs:\n  %s\n  %s", i+1, seen[0], got)
			}
		}
	})

	t.Run("request ids correlate", func(t *testing.T) {
		gw.PDP.Reset()
		resp := call(t, gw.URL, "DELETE", "/api/v1/orders/42", Reader,
			map[string]string{"X-Request-ID": "caller-supplied-id"})
		if got := resp.header.Get("X-Request-ID"); got != "caller-supplied-id" {
			t.Errorf("denial echoed request id %q, want the caller's", got)
		}
		if calls := gw.PDP.Calls(); len(calls) != 1 || calls[0].RequestID != "caller-supplied-id" {
			t.Errorf("the PDP must receive the caller's request id, got %#v", calls)
		}

		gw.PDP.Reset()
		resp = call(t, gw.URL, "DELETE", "/api/v1/orders/42", Reader, nil)
		if resp.header.Get("X-Request-ID") == "" {
			t.Error("a request id must be generated when the caller sends none")
		}
		calls := gw.PDP.Calls()
		if len(calls) != 1 || calls[0].RequestID != resp.header.Get("X-Request-ID") {
			t.Error("the id sent to the PDP must be the one returned to the caller")
		}
		// A generated id must not be presented as one the caller sent.
		if headers, ok := calls[0].Payload["headers"].(map[string]any); ok {
			if _, present := headers["x-request-id"]; present {
				t.Error("a generated request id must not appear in the payload headers")
			}
		}
	})

	t.Run("exactly one decision per request", func(t *testing.T) {
		gw.PDP.Reset()
		call(t, gw.URL, "GET", "/api/v1/orders", Admin, nil)
		if n := len(gw.PDP.Calls()); n != 1 {
			t.Errorf("%d decision calls, want 1 — a retry multiplies a slow PDP", n)
		}
	})

	if gw.UnenforcedPath != "" {
		t.Run("the declared exclusion works and has not widened", func(t *testing.T) {
			gw.PDP.Reset()
			if resp := call(t, gw.URL, "GET", gw.UnenforcedPath, Anonymous, nil); resp.status != http.StatusOK {
				t.Errorf("%s status = %d, want 200 without a token", gw.UnenforcedPath, resp.status)
			}
			if n := len(gw.PDP.Calls()); n != 0 {
				t.Errorf("an excluded route must not call the PDP, got %d calls", n)
			}
			if resp := call(t, gw.URL, "GET", "/api/v1/orders", Anonymous, nil); resp.status == http.StatusOK {
				t.Error("the exclusion has widened to enforced routes")
			}
		})
	}
}

// RunFailsClosed asserts that every request is refused. Call it with the PDP
// stopped. This is the check most worth running: failing open is silent —
// everything keeps working and nothing is enforced.
func RunFailsClosed(t *testing.T, gw Gateway) {
	t.Helper()
	if gw.Denial == (DenialSpec{}) {
		gw.Denial = DefaultDenial
	}
	gw.Backend.Reset()

	for _, c := range []struct{ token, method, path string }{
		{Admin, "GET", "/api/v1/orders"},
		{Admin, "DELETE", "/api/v1/orders/42"},
		{Reader, "GET", "/api/v1/orders"},
		{Anonymous, "GET", "/api/v1/orders"},
	} {
		resp := call(t, gw.URL, c.method, c.path, c.token, nil)
		if resp.status != gw.Denial.StatusCode {
			t.Errorf("%s %s as %s: status = %d, want %d with the PDP down",
				c.method, c.path, identity(c.token), resp.status, gw.Denial.StatusCode)
		}
	}
	if n := len(gw.Backend.Hits()); n != 0 {
		t.Errorf("%d requests reached the backend with the PDP down; enforcement fails open", n)
	}
}

type response struct {
	status int
	header http.Header
	body   string
}

func call(t *testing.T, base, method, path, token string, headers map[string]string, body ...string) response {
	t.Helper()
	var reader io.Reader
	if len(body) > 0 {
		reader = strings.NewReader(body[0])
	}
	req, err := http.NewRequest(method, base+path, reader)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if token != Anonymous {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, header: resp.Header, body: string(raw)}
}

func identity(token string) string {
	if token == Anonymous {
		return "anonymous"
	}
	return token
}
