package plainid

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// ErrBodyTooLarge is returned when a request body exceeds MaxBodyBytes.
// It is a denial: a request that cannot be fully inspected cannot be
// authorized.
var ErrBodyTooLarge = errors.New("plainid: request body exceeds MaxBodyBytes")

// Header names that enforcement reads or writes. Exported for the framework
// adapters, which are the ones that touch the actual request and response.
const (
	RequestIDHeader    = "X-Request-ID"
	AuthorizedByHeader = "X-Authorized-By"
	AuthorizedByValue  = "PlainID"
)

// Request is a framework-neutral description of an inbound HTTP request: the
// only thing the core needs in order to build a decision payload.
//
// Adapters translate their framework's request into this — net/http,
// fasthttp, gin and the rest all populate the same fields — so that payload
// construction, and every rule about its shape, lives in exactly one place.
type Request struct {
	// Method is the HTTP method. Case is normalized for the payload.
	Method string
	// Path is the request path, percent-encoded as it arrived
	// (net/http: r.URL.EscapedPath()).
	Path string
	// Query holds query parameters, one value per key. Where a framework
	// allows repeats, adapters keep the first.
	Query map[string]string
	// Header holds the inbound headers in whatever case they arrived; the
	// payload lower-cases them.
	Header map[string][]string
	// Scheme is "http" or "https" as the adapter sees it. With
	// TrustForwardedHeaders set, X-Forwarded-Proto overrides it.
	Scheme string
	// RemoteAddr is the peer address, with or without a port. With
	// TrustForwardedHeaders set, X-Forwarded-For overrides it.
	RemoteAddr string
	// Body is the request body, already read and size-capped by the adapter
	// (see ReadCappedBody). Nil or empty means the payload carries no body.
	Body []byte
}

// URI is the uri member of the decision payload.
type URI struct {
	// Path is the full path followed by its "/"-split segments. See buildPath.
	Path []string `json:"path"`
	// Query holds query parameters as a flat object of string values.
	Query map[string]string `json:"query"`
	// Schema is "http" or "https". Note the spelling: the API says "schema".
	Schema string `json:"schema"`
}

// Meta is the meta member of the decision payload.
type Meta struct {
	RuntimeFineTune map[string]any `json:"runtimeFineTune"`
}

// Payload is the body POSTed to the PDP's permit-deny endpoint.
type Payload struct {
	IPAddress            string              `json:"ipAddress,omitempty"`
	Method               string              `json:"method"`
	URI                  URI                 `json:"uri"`
	Headers              map[string][]string `json:"headers"`
	RequestID            string              `json:"requestId,omitempty"`
	AuthenticationMethod string              `json:"authenticationMethod"`
	Meta                 Meta                `json:"meta"`
	// Body is present only when the request has a non-empty body: parsed JSON
	// when it parses, otherwise the raw string.
	Body any `json:"body,omitempty"`
}

// BuildPayload turns a neutral Request into the decision payload. Adapters
// rarely need it directly — AuthorizeRequest calls it — but it is exported so
// a payload can be inspected or unit-tested on its own.
func (c *Client) BuildPayload(req Request, requestID string) Payload {
	p := Payload{
		IPAddress:            c.cfg.clientIP(req),
		Method:               strings.ToUpper(req.Method),
		Headers:              buildHeaders(req.Header),
		RequestID:            requestID,
		AuthenticationMethod: c.cfg.AuthMethod,
		Meta:                 Meta{RuntimeFineTune: c.cfg.RuntimeFineTune},
		URI: URI{
			Path:   buildPath(req.Path),
			Query:  buildQuery(req.Query),
			Schema: c.cfg.scheme(req),
		},
	}
	if len(req.Body) > 0 {
		p.Body = decodeBody(req.Body)
	}
	return p
}

// buildPath builds the payload's path array: the full path at index 0, then
// its "/"-split segments, without the empty segment the leading slash produces.
//
//	/api/v1/orders/42 → ["/api/v1/orders/42", "api", "v1", "orders", "42"]
//
// Policies are authored against this shape, matching either the whole path at
// index 0 or a segment at a known index, so the indexes have to line up. A
// mismatch here denies everything with no error anywhere — verify against a
// path with several segments before trusting a change to it.
func buildPath(path string) []string {
	if path == "" {
		path = "/"
	}
	segments := strings.Split(path, "/")
	if len(segments) > 0 && segments[0] == "" {
		segments = segments[1:] // drop the empty segment before the leading slash
	}
	out := make([]string, 0, len(segments)+1)
	out = append(out, path)
	return append(out, segments...)
}

// buildQuery copies the query map, never returning nil: the payload's query is
// a flat object, and must serialize as {} rather than null.
func buildQuery(q map[string]string) map[string]string {
	out := make(map[string]string, len(q))
	for k, v := range q {
		out[k] = v
	}
	return out
}

// buildHeaders lower-cases every header name and splits each value on commas,
// skipping empty headers.
func buildHeaders(h map[string][]string) map[string][]string {
	out := make(map[string][]string, len(h))
	for name, values := range h {
		var parts []string
		for _, v := range values {
			for _, piece := range strings.Split(v, ",") {
				if piece = strings.TrimSpace(piece); piece != "" {
					parts = append(parts, piece)
				}
			}
		}
		if len(parts) > 0 {
			out[strings.ToLower(name)] = parts
		}
	}
	return out
}

// ReadCappedBody reads at most max bytes from body and returns them. A body
// larger than max returns ErrBodyTooLarge, which callers must treat as a
// denial rather than truncating: a request that cannot be fully inspected
// cannot be authorized.
//
// Adapters whose framework streams the body (net/http) use this and then
// replay the bytes to the backend; adapters that already hold the body in
// memory (fasthttp) can pass it straight to Request.Body, where the same limit
// is enforced.
func ReadCappedBody(body io.Reader, max int64) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	// One byte past the limit distinguishes "exactly at the limit" from "over".
	data, err := io.ReadAll(io.LimitReader(body, max+1))
	if err != nil {
		return nil, fmt.Errorf("plainid: reading request body: %w", err)
	}
	if int64(len(data)) > max {
		return nil, ErrBodyTooLarge
	}
	return data, nil
}

// decodeBody returns parsed JSON when the body parses, and the raw string
// otherwise. An unparseable body is not a denial: the operation being
// authorized is identified by method and URI.
func decodeBody(data []byte) any {
	var parsed any
	if err := json.Unmarshal(data, &parsed); err == nil {
		return parsed
	}
	return string(data)
}

// clientIP returns the caller's address. Behind another proxy this is the
// proxy's address unless TrustForwardedHeaders resolves X-Forwarded-For.
func (c Config) clientIP(req Request) string {
	if c.TrustForwardedHeaders {
		if xff := headerValue(req.Header, "X-Forwarded-For"); xff != "" {
			if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
				return first
			}
		}
	}
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		return host
	}
	return req.RemoteAddr
}

// scheme returns "http" or "https" for uri.schema.
func (c Config) scheme(req Request) string {
	if c.TrustForwardedHeaders {
		if proto := headerValue(req.Header, "X-Forwarded-Proto"); proto != "" {
			return strings.ToLower(strings.TrimSpace(strings.Split(proto, ",")[0]))
		}
	}
	if req.Scheme != "" {
		return strings.ToLower(req.Scheme)
	}
	return "http"
}

// headerValue reads a header from a neutral header map, matching the name
// case-insensitively — adapters hand over whatever casing arrived on the wire.
func headerValue(h map[string][]string, name string) string {
	for existing, values := range h {
		if strings.EqualFold(existing, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// NewRequestID generates an RFC 4122 version 4 UUID, used when the caller
// supplied no X-Request-ID.
func NewRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not recoverable here; a non-unique id is
		// worse than an obviously synthetic one.
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
