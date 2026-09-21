// Package plainidfasthttp authorizes fasthttp requests against a PlainID PDP
// before they reach the handler behind it.
//
// It is a translation layer and nothing more: the decision, the payload shape,
// the fail-closed rules and the uniform denial all live in the core package,
// shared with every other adapter.
//
// This is a separate Go module, so that projects using net/http do not inherit
// the fasthttp dependency. Import it as:
//
//	go get github.com/plainidio/plainid-go-authz/middleware/fasthttp
package plainidfasthttp

import (
	"github.com/plainidio/plainid-go-authz/plainid"
	"github.com/valyala/fasthttp"
)

// Enforcer holds a configured client and the fasthttp-specific options.
// Create one per process and reuse it, so connections to the PDP are pooled.
type Enforcer struct {
	client *plainid.Client
	skip   func(*fasthttp.RequestCtx) bool
}

// Option configures an Enforcer.
type Option func(*Enforcer)

// WithSkip excludes requests from enforcement entirely. Health checks, metrics
// and OPTIONS preflight are the usual cases.
//
// Every exclusion is a hole: keep it declared here, in one place, rather than
// implied by routing, and list it in your README. An undocumented exclusion is
// indistinguishable from a bypass.
func WithSkip(skip func(*fasthttp.RequestCtx) bool) Option {
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

// Middleware returns middleware ready to wrap a fasthttp.RequestHandler.
// Equivalent to New followed by Handler.
func Middleware(cfg plainid.Config, opts ...Option) (func(fasthttp.RequestHandler) fasthttp.RequestHandler, error) {
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
// unmodified apart from a normalized X-Request-ID and X-Authorized-By.
func (e *Enforcer) Handler(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if e.skip != nil && e.skip(ctx) {
			next(ctx)
			return
		}
		if decision := e.Authorize(ctx); !decision.Permit {
			e.WriteDenial(ctx, decision.RequestID)
			return
		}
		next(ctx)
	}
}

// Authorize makes the decision for ctx and logs it, without writing anything
// to the client — for enforcing somewhere other than a handler chain. The
// caller writes WriteDenial on anything but a permit.
//
// It mutates the request exactly as Handler does: X-Request-ID is normalized
// or generated whatever the verdict, and X-Authorized-By is added on permit.
//
// fasthttp.RequestCtx implements context.Context, so the decision call is
// bound to the request's own deadline.
func (e *Enforcer) Authorize(ctx *fasthttp.RequestCtx) plainid.Decision {
	req := request(ctx)

	decision := e.client.AuthorizeRequest(ctx, req)

	// Stamp the request id before branching, not just on permit, so an outer
	// middleware such as a request logger can correlate a denied request with
	// the PDP's audit record. The payload was already built from the caller's
	// own headers, so a generated id never leaks into it.
	setHeader(ctx, plainid.RequestIDHeader, decision.RequestID)

	if !decision.Permit {
		e.client.LogDenial(req, decision)
		return decision
	}
	e.client.LogPermit(req, decision)

	// The only other change enforcement makes to a permitted request.
	ctx.Request.Header.Set(plainid.AuthorizedByHeader, plainid.AuthorizedByValue)
	return decision
}

// WriteDenial writes the single configured refusal response. Policy denials
// and PDP outages are indistinguishable to the caller by design — the
// difference belongs in the logs, not in the response.
func (e *Enforcer) WriteDenial(ctx *fasthttp.RequestCtx, requestID string) {
	denial := e.client.Denial()
	ctx.Response.Reset()
	ctx.SetStatusCode(denial.StatusCode)
	ctx.SetContentType(denial.ContentType)
	if requestID != "" {
		ctx.Response.Header.Set(plainid.RequestIDHeader, requestID)
	}
	ctx.SetBodyString(denial.Body)
}

// request translates a fasthttp request into the neutral form the core works
// with. The body is already in memory here, so unlike the net/http adapter
// there is nothing to read and replay — the size limit is enforced by the core.
func request(ctx *fasthttp.RequestCtx) plainid.Request {
	return plainid.Request{
		Method:     string(ctx.Method()),
		Path:       path(ctx),
		Query:      query(ctx),
		Header:     header(ctx),
		Scheme:     scheme(ctx),
		RemoteAddr: ctx.RemoteAddr().String(),
		Body:       ctx.PostBody(),
	}
}

// path returns the request path as it arrived. PathOriginal is used rather
// than Path, which fasthttp has already normalized and percent-decoded: the
// PDP must judge the path the caller actually sent, and the net/http adapter
// sends the escaped form too.
func path(ctx *fasthttp.RequestCtx) string {
	if p := ctx.URI().PathOriginal(); len(p) > 0 {
		return string(p)
	}
	return string(ctx.Path())
}

// query flattens the query string to one value per key, keeping the first
// occurrence — the payload's query is a flat object, not a multimap.
func query(ctx *fasthttp.RequestCtx) map[string]string {
	q := map[string]string{}
	ctx.QueryArgs().VisitAll(func(key, value []byte) {
		if _, seen := q[string(key)]; !seen {
			q[string(key)] = string(value)
		}
	})
	return q
}

// header collects the inbound headers, keeping repeats of the same name.
func header(ctx *fasthttp.RequestCtx) map[string][]string {
	h := map[string][]string{}
	ctx.Request.Header.VisitAll(func(key, value []byte) {
		name := string(key)
		h[name] = append(h[name], string(value))
	})
	return h
}

// scheme reports how the caller reached this server. X-Forwarded-Proto is
// applied by the core, and only when TrustForwardedHeaders is set.
func scheme(ctx *fasthttp.RequestCtx) string {
	if ctx.IsTLS() {
		return "https"
	}
	if s := ctx.URI().Scheme(); len(s) > 0 {
		return string(s)
	}
	return "http"
}

// setHeader replaces a request header. fasthttp stores header names
// case-insensitively and normalizes them on write, so unlike net/http there is
// no differently-cased duplicate to remove first.
func setHeader(ctx *fasthttp.RequestCtx, name, value string) {
	ctx.Request.Header.Set(name, value)
}
