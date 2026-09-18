package plainid

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// permitResult is the only value that allows a request through.
const permitResult = "PERMIT"

// maxPDPResponseBytes bounds what is read back from the PDP. The answer is a
// small JSON object; anything larger is a misconfigured URL, not a decision.
const maxPDPResponseBytes = 1 << 20

// decisionResponse is the permit-deny answer: {"data": {"result": "PERMIT"}}.
//
// Note this is a different shape from the MCP variant of this pattern, which
// reads data.data[0].output.accessResponse.result. Which shape comes back is
// determined by the request, not the endpoint.
type decisionResponse struct {
	Data struct {
		Result string `json:"result"`
	} `json:"data"`
}

// Decision is the outcome of one PDP call.
type Decision struct {
	// Permit is true only when the PDP answered with the exact string PERMIT.
	Permit bool
	// Result is the raw result string, empty if none was returned.
	Result string
	// RequestID correlates this decision with the PDP's audit record.
	RequestID string
	// Reason describes why a request was refused, for logs only. It is never
	// shown to the caller.
	Reason string
	// Err is set when the refusal came from a failure rather than a policy.
	Err error
}

// Authorizer makes permit-deny decisions against a PlainID PDP. It is safe for
// concurrent use and should be created once and reused, so that connections to
// the PDP are pooled.
type Authorizer struct {
	cfg      Config
	endpoint string
}

// New validates the configuration and returns an Authorizer.
func New(cfg Config) (*Authorizer, error) {
	c, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	return &Authorizer{cfg: c, endpoint: c.URL + decisionPath}, nil
}

// defaultHTTPClient returns a pooled keep-alive client. Reusing connections
// matters: at API volume a fresh TLS handshake per request can cost more than
// the decision it carries.
func defaultHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 256
	transport.MaxIdleConnsPerHost = 64
	transport.IdleConnTimeout = 90 * time.Second
	return &http.Client{Transport: transport, Timeout: timeout}
}

// Config returns the normalized configuration in use.
func (a *Authorizer) Config() Config { return a.cfg }

// AuthorizeRequest builds the decision payload from a neutral Request and asks
// the PDP. This is the entry point every framework adapter uses.
//
// It fails closed: every path that is not an explicit PERMIT returns a
// Decision with Permit false.
func (a *Authorizer) AuthorizeRequest(ctx context.Context, req Request) Decision {
	requestID := a.RequestID(req.Header)

	// Adapters that stream the body cap it with ReadCappedBody before they get
	// here; this catches the ones that hand over an in-memory body.
	if int64(len(req.Body)) > a.cfg.MaxBodyBytes {
		return Decision{
			RequestID: requestID,
			Reason:    "request body exceeds MaxBodyBytes",
			Err:       ErrBodyTooLarge,
		}
	}
	return a.Decide(ctx, a.BuildPayload(req, requestID), requestID)
}

// RequestID keeps the caller's X-Request-ID when present — the lookup is
// case-insensitive, so a client sending x-request-id does not get a second,
// differently-cased header generated alongside it — and generates one
// otherwise.
func (a *Authorizer) RequestID(header map[string][]string) string {
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
func (a *Authorizer) Denial() Denial {
	return Denial{
		StatusCode:  a.cfg.OnPreventStatusCode,
		Body:        a.cfg.OnPreventBody,
		ContentType: a.cfg.OnPreventContentType,
	}
}

// LogDenial records precisely what the refusal response deliberately hides.
// Adapters call it so that every port logs a denial the same way.
func (a *Authorizer) LogDenial(req Request, d Decision) {
	args := []any{
		"requestId", d.RequestID,
		"method", req.Method,
		"path", req.Path,
		"ip", a.cfg.clientIP(req),
		"reason", d.Reason,
		"result", d.Result,
	}
	if d.Err != nil {
		args = append(args, "error", d.Err)
	}
	a.cfg.Logger.Warn("plainid: denied", args...)
}

// LogPermit records a permitted request when tracing is on.
func (a *Authorizer) LogPermit(req Request, d Decision) {
	if !a.cfg.EnableTracing {
		return
	}
	a.cfg.Logger.Info("plainid: permit",
		"requestId", d.RequestID, "method", req.Method, "path", req.Path)
}

// Decide sends an already-built payload to the PDP. Exposed for callers that
// enforce somewhere other than an http.Handler.
func (a *Authorizer) Decide(ctx context.Context, payload Payload, requestID string) Decision {
	d := Decision{RequestID: requestID}

	body, err := json.Marshal(payload)
	if err != nil {
		d.Reason, d.Err = "payload is not encodable", err
		return d
	}
	if a.cfg.EnableTracing {
		a.cfg.Logger.Info("plainid: decision request",
			"requestId", requestID, "endpoint", a.endpoint, "payload", json.RawMessage(body))
	}

	// One decision per request: the timeout bounds the whole call, and there
	// is no retry — a retry turns one slow call into several.
	ctx, cancel := context.WithTimeout(ctx, a.cfg.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		d.Reason, d.Err = "could not build PDP request", err
		return d
	}
	a.setDecisionHeaders(req, payload, requestID)

	resp, err := a.cfg.HTTPClient.Do(req)
	if err != nil {
		d.Reason, d.Err = "PDP unreachable", err
		return d
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxPDPResponseBytes))
	if err != nil {
		d.Reason, d.Err = "PDP response unreadable", err
		return d
	}
	if a.cfg.EnableTracing {
		a.cfg.Logger.Info("plainid: decision response",
			"requestId", requestID, "status", resp.StatusCode, "body", string(raw))
	}
	if resp.StatusCode != http.StatusOK {
		d.Reason = fmt.Sprintf("PDP returned status %d", resp.StatusCode)
		d.Err = fmt.Errorf("plainid: PDP status %d: %s", resp.StatusCode, truncate(raw, 512))
		return d
	}

	var parsed decisionResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		d.Reason, d.Err = "PDP response unparseable", err
		return d
	}
	d.Result = parsed.Data.Result
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

// setDecisionHeaders applies the credential headers for the configured auth
// method, plus any inbound headers named by HeadersToForward.
func (a *Authorizer) setDecisionHeaders(req *http.Request, payload Payload, requestID string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(RequestIDHeader, requestID)

	if a.cfg.ClientID != "" {
		req.Header.Set(a.cfg.ClientIDHeader, a.cfg.ClientID)
	}
	switch a.cfg.AuthMethod {
	case AuthMethodToken:
		// The caller's own bearer token identifies them to the PDP.
		if auth := forwardedHeader(payload.Headers, "authorization"); auth != "" {
			req.Header.Set("Authorization", auth)
		}
	case AuthMethodSecret:
		// The gateway authenticates itself; the caller's identity reaches the
		// PDP through the payload's headers field instead.
		req.Header.Set(a.cfg.ClientSecretHeader, a.cfg.ClientSecret)
	}

	for _, name := range a.cfg.HeadersToForward {
		if v := forwardedHeader(payload.Headers, name); v != "" {
			req.Header.Set(name, v)
		}
	}
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

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
