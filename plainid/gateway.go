package plainid

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// The 5.0 and v3 endpoints share one answer shape, read by permitDenyResponse,
// which accepts both the documented {"data":{"result":…}} envelope and the
// top-level {"result":…} some deployments return.
//
// The token and resolution APIs are different again — a top-level "response"
// array carrying no result at all. Copying a reader between those denies or
// permits everything, depending on direction.

// AuthorizeRequest builds the 5.0 decision payload from a neutral Request and
// asks the PDP: "may this caller make this HTTP request?"
//
// This is the entry point every framework adapter uses. It fails closed:
// every path that is not an explicit PERMIT returns a Decision with Permit
// false.
func (c *Client) AuthorizeRequest(ctx context.Context, req Request) Decision {
	requestID := c.RequestID(req.Header)

	// Adapters that stream the body cap it with ReadCappedBody before they get
	// here; this catches the ones that hand over an in-memory body.
	if int64(len(req.Body)) > c.cfg.MaxBodyBytes {
		return Decision{
			RequestID: requestID,
			Reason:    "request body exceeds MaxBodyBytes",
			Err:       ErrBodyTooLarge,
		}
	}
	return c.Decide(ctx, c.BuildPayload(req, requestID), requestID)
}

// Decide sends an already-built 5.0 payload to the PDP. Exposed for callers
// that enforce somewhere other than an http.Handler.
func (c *Client) Decide(ctx context.Context, payload Payload, requestID string) Decision {
	d := Decision{RequestID: requestID}

	raw, perr := c.post(ctx, c.endpoints.decision, payload, requestID, c.requestAuth(payload))
	if perr != nil {
		d.Reason, d.Err = perr.Reason, perr
		return d
	}

	var parsed permitDenyResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		d.Reason, d.Err = "PDP response unparseable", &pdpError{Reason: "PDP response unparseable", Err: err}
		return d
	}
	d.Result = parsed.body().Result
	if d.Result != permitResult {
		if d.Result == "" {
			d.Reason = "PDP response has no data.result"
		} else {
			d.Reason = "policy denied"
		}
		return d
	}
	d.Permit = true
	return d
}

// requestAuth applies the credential headers for the configured auth method,
// plus any inbound headers named by HeadersToForward.
//
// This differs from appAuth, which the v3 endpoints use: here the caller's own
// bearer token can be what identifies them to the PDP, so the credentials come
// partly from the request being authorized.
func (c *Client) requestAuth(payload Payload) func(http.Header) {
	return func(h http.Header) {
		if c.cfg.ClientID != "" {
			h.Set(c.cfg.ClientIDHeader, c.cfg.ClientID)
		}
		switch c.cfg.AuthMethod {
		case AuthMethodToken:
			// The caller's own bearer token identifies them to the PDP.
			if auth := forwardedHeader(payload.Headers, "authorization"); auth != "" {
				h.Set("Authorization", auth)
			}
		case AuthMethodSecret:
			// The gateway authenticates itself; the caller's identity reaches
			// the PDP through the payload's headers field instead.
			h.Set(c.cfg.ClientSecretHeader, c.cfg.ClientSecret)
		}

		for _, name := range c.cfg.HeadersToForward {
			if v := forwardedHeader(payload.Headers, name); v != "" {
				h.Set(name, v)
			}
		}
	}
}

// RequestID keeps the caller's X-Request-ID when present — the lookup is
// case-insensitive, so a client sending x-request-id does not get a second,
// differently-cased header generated alongside it — and generates one
// otherwise.
func (c *Client) RequestID(header map[string][]string) string {
	if id := headerValue(header, RequestIDHeader); id != "" {
		return id
	}
	return NewRequestID()
}

// Denial describes the single response returned for every refusal. Adapters
// write it in whatever way their framework expects; the values come from
// configuration so that every port refuses identically.
type Denial struct {
	StatusCode  int
	Body        string
	ContentType string
}

// Denial returns the configured refusal response.
func (c *Client) Denial() Denial {
	return Denial{
		StatusCode:  c.cfg.OnPreventStatusCode,
		Body:        c.cfg.OnPreventBody,
		ContentType: c.cfg.OnPreventContentType,
	}
}

// LogDenial records precisely what the refusal response deliberately hides.
// Adapters call it so that every port logs a denial the same way.
func (c *Client) LogDenial(req Request, d Decision) {
	args := []any{
		"requestId", d.RequestID,
		"method", req.Method,
		"path", req.Path,
		"ip", c.cfg.clientIP(req),
		"reason", d.Reason,
		"result", d.Result,
		// The one distinction that matters on call: policy said no, versus
		// the PDP never answered.
		"failure", d.Failed(),
	}
	if d.Err != nil {
		args = append(args, "error", d.Err)
	}
	c.cfg.Logger.Warn("plainid: denied", args...)
}

// LogPermit records a permitted request when tracing is on.
func (c *Client) LogPermit(req Request, d Decision) {
	if !c.cfg.EnableTracing {
		return
	}
	c.cfg.Logger.Info("plainid: permit",
		"requestId", d.RequestID, "method", req.Method, "path", req.Path)
}

// forwardedHeader looks a name up in the lower-cased payload header map and
// rejoins the comma-split parts, so the value forwarded to the PDP matches what
// the caller actually sent.
func forwardedHeader(headers map[string][]string, name string) string {
	if v, ok := headers[strings.ToLower(name)]; ok && len(v) > 0 {
		return strings.Join(v, ", ")
	}
	return ""
}
