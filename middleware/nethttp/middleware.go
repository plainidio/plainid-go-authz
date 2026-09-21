// Package plainidhttp authorizes net/http requests against a PlainID PDP
// before they reach the handler behind it.
//
// It wraps any http.Handler, so it covers net/http itself and everything built
// on it — chi, gorilla/mux, httputil.ReverseProxy — none of which need an
// adapter of their own, since they all compose func(http.Handler) http.Handler.
//
// The decision itself lives in the core package: this one only translates
// between net/http and plainid.Request, and writes the refusal. It holds a
// *plainid.Client — the same client your handlers use for Can and
// Permissions — so route enforcement and in-handler checks share one
// configuration, one pooled connection to the PDP, and one set of
// fail-closed rules.
package plainidhttp

import (
	"net/http"
	"strings"

	"github.com/plainidio/plainid-go-authz/plainid"
)

// Enforcer holds a configured client and the net/http-specific options.
// Create one per process and reuse it, so connections to the PDP are pooled.
type Enforcer struct {
	client *plainid.Client
	skip   func(*http.Request) bool
}

// Option configures an Enforcer.
type Option func(*Enforcer)

// WithSkip excludes requests from enforcement entirely. Health checks, metrics
// and OPTIONS preflight are the usual cases.
//
// Every exclusion is a hole: keep it declared here, in one place, rather than
// implied by routing, and list it in your README. An undocumented exclusion is
// indistinguishable from a bypass.
func WithSkip(skip func(*http.Request) bool) Option {
	return func(e *Enforcer) { e.skip = skip }
}

// New builds an Enforcer from a core configuration.
func New(cfg plainid.Config, opts ...Option) (*Enforcer, error) {
	a, err := plainid.New(cfg)
	if err != nil {
		return nil, err
	}
	e := &Enforcer{client: a}
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
}

// Middleware returns middleware ready to compose with other
// func(http.Handler) http.Handler wrappers. Equivalent to New followed by
// Handler.
func Middleware(cfg plainid.Config, opts ...Option) (func(http.Handler) http.Handler, error) {
	e, err := New(cfg, opts...)
	if err != nil {
		return nil, err
	}
	return e.Handler, nil
}

// Client returns the underlying core client, so a handler behind this
// middleware can ask its own domain-level questions — Can, Check,
// Permissions — without building a second client or a second connection pool.
func (e *Enforcer) Client() *plainid.Client { return e.client }

// Authorizer is the former name of Client.
//
// Deprecated: use Client.
func (e *Enforcer) Authorizer() *plainid.Client { return e.client }

// Handler wraps next with enforcement. Permitted requests reach next
// byte-identical apart from a normalized X-Request-ID and X-Authorized-By.
func (e *Enforcer) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e.skip != nil && e.skip(r) {
			next.ServeHTTP(w, r)
			return
		}
		if decision := e.Authorize(r); !decision.Permit {
			e.deny(w, decision.RequestID)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Authorize makes the decision for r and logs it, without writing anything to
// the client — for enforcing somewhere other than a handler chain. The caller
// writes WriteDenial on anything but a permit.
//
// It mutates r exactly as Handler does: X-Request-ID is normalized or
// generated whatever the verdict, and X-Authorized-By is added on permit. It
// also consumes and restores r.Body, so r stays forwardable.
//
// It fails closed: an unreadable or oversized body is a refusal like any other.
func (e *Enforcer) Authorize(r *http.Request) plainid.Decision {
	req, err := e.request(r)
	if err != nil {
		// A body that cannot be read or is over the limit cannot be fully
		// inspected, so it cannot be authorized.
		d := plainid.Decision{
			RequestID: e.client.RequestID(r.Header),
			Reason:    "request body unusable",
			Err:       err,
		}
		setHeaderFold(r.Header, plainid.RequestIDHeader, d.RequestID)
		e.client.LogDenial(req, d)
		return d
	}

	decision := e.client.AuthorizeRequest(r.Context(), req)

	// Stamp the request id before branching, not just on permit: the header
	// map is shared with any outer middleware, so a logger wrapping this one
	// can correlate a *denied* request with the PDP's audit record too. The
	// decision payload was already built from the caller's own headers, so a
	// generated id never leaks into it.
	setHeaderFold(r.Header, plainid.RequestIDHeader, decision.RequestID)

	if !decision.Permit {
		e.client.LogDenial(req, decision)
		return decision
	}
	e.client.LogPermit(req, decision)

	// The only other change enforcement makes to a permitted request.
	r.Header.Set(plainid.AuthorizedByHeader, plainid.AuthorizedByValue)
	return decision
}

// request translates an inbound *http.Request into the neutral form the core
// works with. It consumes r.Body and replaces it with an equivalent reader, so
// the request stays forwardable to the backend.
func (e *Enforcer) request(r *http.Request) (plainid.Request, error) {
	req := plainid.Request{
		Method:     r.Method,
		Path:       r.URL.EscapedPath(),
		Query:      query(r),
		Header:     r.Header,
		Scheme:     scheme(r),
		RemoteAddr: r.RemoteAddr,
	}

	body, err := plainid.ReadCappedBody(bodyReader(r), e.client.Config().MaxBodyBytes)
	if err != nil {
		r.Body.Close()
		return req, err
	}
	if len(body) > 0 {
		replaceBody(r, body)
		req.Body = body
	}
	return req, nil
}

// WriteDenial writes the single configured refusal response. Policy denials
// and PDP outages are indistinguishable to the caller by design — the
// difference belongs in the logs, not in the response.
func (e *Enforcer) WriteDenial(w http.ResponseWriter, requestID string) {
	e.deny(w, requestID)
}

func (e *Enforcer) deny(w http.ResponseWriter, requestID string) {
	denial := e.client.Denial()
	h := w.Header()
	h.Set("Content-Type", denial.ContentType)
	if requestID != "" {
		setHeaderFold(h, plainid.RequestIDHeader, requestID)
	}
	w.WriteHeader(denial.StatusCode)
	_, _ = w.Write([]byte(denial.Body))
}

// query flattens the query string to one value per key, keeping the first
// occurrence — the payload's query is a flat object, not a multimap.
func query(r *http.Request) map[string]string {
	q := map[string]string{}
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			q[k] = v[0]
		}
	}
	return q
}

// scheme reports how the caller reached this server. X-Forwarded-Proto is
// applied by the core, and only when TrustForwardedHeaders is set.
func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if r.URL != nil && r.URL.Scheme != "" {
		return strings.ToLower(r.URL.Scheme)
	}
	return "http"
}

// setHeaderFold sets a header, first removing every differently-cased copy of
// it, so a caller who sent "x-request-id" does not end up with a second,
// canonically-cased header alongside their own. The value is stored under Go's
// canonical spelling so that Header.Get finds it downstream; HTTP header names
// are case-insensitive on the wire.
func setHeaderFold(h http.Header, name, value string) {
	for existing := range h {
		if strings.EqualFold(existing, name) {
			delete(h, existing)
		}
	}
	h.Set(name, value)
}
