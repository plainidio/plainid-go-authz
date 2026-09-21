package plainid

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Endpoint paths, appended to the configured base URL. They are three
// different questions, not three flavours of one:
//
//	decisionPath    may this caller make *this HTTP request*?      (5.0)
//	permitDenyPath  may this user do *this* to *this object*?      (v3)
//	tokenPath       what may this user do at all?                  (v3)
//
// A URL copied between the first two produces confusing 400s or blanket
// denials, since their payloads are shaped completely differently.
const (
	decisionPath   = "/runtime/5.0/decisions/permit-deny"
	permitDenyPath = "/runtime/permit-deny/v3"
	tokenPath      = "/runtime/token/v3"
)

// authorizationHeader is the default header an end user's JWT arrives in,
// and the one an application's own bearer token would use.
const authorizationHeader = "Authorization"

// permitResult is the only value that allows anything through.
const permitResult = "PERMIT"

// maxPDPResponseBytes bounds what is read back from the PDP. A permit-deny
// answer is a small JSON object; an access token is larger but still bounded.
const maxPDPResponseBytes = 4 << 20

// Client calls the PlainID Runtime Authorization APIs. It is safe for
// concurrent use and should be created once per process and reused, so that
// connections to the PDP are pooled — at request volume a fresh TLS handshake
// can cost more than the decision it carries.
//
// Three surfaces sit on it, one per question:
//
//	AuthorizeRequest  an inbound HTTP request           → Decision   (5.0)
//	Can / Check       a user, an action, a domain object → Decision  (v3)
//	Permissions       everything a user may do           → Permissions
//
// Every one of them fails closed: no error path returns a permit, and no
// error path returns permissions.
type Client struct {
	cfg       Config
	endpoints endpoints
}

type endpoints struct {
	decision   string
	permitDeny string
	token      string
}

// Authorizer is the former name of Client, from when this package only made
// gateway-style decisions on HTTP requests.
//
// Deprecated: use Client.
type Authorizer = Client

// New validates the configuration and returns a Client. Configuration is
// checked once, here, so that a bad timeout or auth method fails at startup
// rather than at request time — where it would look exactly like a policy
// problem and get debugged as one.
func New(cfg Config) (*Client, error) {
	c, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg: c,
		endpoints: endpoints{
			decision:   c.URL + decisionPath,
			permitDeny: c.URL + permitDenyPath,
			token:      c.URL + tokenPath,
		},
	}, nil
}

// Config returns the normalized configuration in use.
func (c *Client) Config() Config { return c.cfg }

// defaultHTTPClient returns a pooled keep-alive client.
func defaultHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 256
	transport.MaxIdleConnsPerHost = 64
	transport.IdleConnTimeout = 90 * time.Second
	return &http.Client{Transport: transport, Timeout: timeout}
}

// ErrPDPUnavailable wraps every failure to obtain an answer from the PDP:
// unreachable, timed out, non-200, or a body that will not parse. It is
// deliberately distinct from a policy denial — the two demand completely
// different responses, and once they look alike in logs the fail-closed
// design starts to feel like a liability.
var ErrPDPUnavailable = errors.New("plainid: no usable answer from the PDP")

// pdpError is the internal failure type. Reason is the short phrase that goes
// into logs and into Decision.Reason.
type pdpError struct {
	Reason string
	Status int
	Err    error
}

func (e *pdpError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("plainid: %s: %v", e.Reason, e.Err)
	}
	return "plainid: " + e.Reason
}

func (e *pdpError) Unwrap() error { return ErrPDPUnavailable }

// post sends payload to one runtime endpoint and returns the raw 200 body.
// Every non-200 outcome — including a transport failure — comes back as a
// *pdpError, so each API's caller can turn it into its own closed answer.
//
// There is no retry. Retrying a timeout turns one slow call into several and
// can take down the service the authorization was protecting.
func (c *Client) post(ctx context.Context, endpoint string, payload any, requestID string, auth func(http.Header)) ([]byte, *pdpError) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, &pdpError{Reason: "payload is not encodable", Err: err}
	}
	c.trace("plainid: runtime request", requestID, "endpoint", endpoint, "payload", redact(body))

	ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, &pdpError{Reason: "could not build PDP request", Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(RequestIDHeader, requestID)
	auth(req.Header)

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, &pdpError{Reason: "PDP unreachable", Err: err}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxPDPResponseBytes))
	if err != nil {
		return nil, &pdpError{Reason: "PDP response unreadable", Status: resp.StatusCode, Err: err}
	}
	c.trace("plainid: runtime response", requestID, "endpoint", endpoint, "status", resp.StatusCode, "body", string(raw))

	if resp.StatusCode != http.StatusOK {
		// 401/403 here is the *application* failing to authenticate, or the
		// identity not resolving — not a policy denial. The PDP says which in
		// the body, so put it in the reason: "PDP returned status 403" on its
		// own sends people to read their own code, and the answer is usually
		// RT-087 sitting right there in the response.
		return nil, &pdpError{
			Reason: fmt.Sprintf("PDP returned status %d: %s", resp.StatusCode, describePDPError(raw)),
			Status: resp.StatusCode,
			Err:    fmt.Errorf("plainid: PDP status %d: %s", resp.StatusCode, truncate(raw, 512)),
		}
	}
	return raw, nil
}

// authPlan is the resolved set of credentials for one call: who the
// application is, and — separately — who the end user is.
//
// The two are genuinely different things, and conflating them is how a client
// ends up authenticating as nobody. Every v3 endpoint authenticates the
// *calling application* (a PlainID Scope). The end user is described either as
// data in the payload (entityId + entityTypeId) or, when the caller arrives
// with a JWT, by that token in a header the PDP resolves the identity from.
type authPlan struct {
	identityHeader string // header carrying the end user's JWT, if any
	identityToken  string
	appBearer      string // Authorization bearer authenticating the application
	appSecret      bool   // send the Scope's client secret
}

// resolveAuth decides which credential goes in which header, and refuses when
// two of them want the same one.
//
// The rule: an identity JWT owns Config.IdentityTokenHeader, and the
// application then authenticates with its client id and secret. If the
// identity header is Authorization and the only application credential is a
// bearer token, there is no way to send both — that is a configuration
// mistake, and this returns an error rather than silently dropping one, which
// would authenticate as nobody and deny everything.
func (c *Client) resolveAuth(identityToken, callBearer string) (authPlan, error) {
	p := authPlan{}
	if identityToken != "" {
		p.identityHeader = c.cfg.IdentityTokenHeader
		p.identityToken = identityToken
	}

	appBearer := callBearer
	if appBearer == "" {
		appBearer = c.cfg.BearerToken
	}
	collides := p.identityHeader != "" && strings.EqualFold(p.identityHeader, authorizationHeader)

	switch {
	case c.cfg.ClientSecret != "" && (collides || appBearer == ""):
		p.appSecret = true
	case appBearer != "":
		if collides {
			return p, fmt.Errorf(
				"plainid: the end user's JWT and this application's bearer token both target the %s header; "+
					"authenticate the application with PLAINID_CLIENT_SECRET, or move the identity token to another "+
					"header with PLAINID_IDENTITY_TOKEN_HEADER", c.cfg.IdentityTokenHeader)
		}
		p.appBearer = appBearer
	}
	return p, nil
}

// apply writes the plan onto an outbound request.
func (c *Client) apply(p authPlan) func(http.Header) {
	return func(h http.Header) {
		if c.cfg.ClientID != "" {
			h.Set(c.cfg.ClientIDHeader, c.cfg.ClientID)
		}
		if p.identityToken != "" {
			h.Set(p.identityHeader, identityHeaderValue(p.identityHeader, p.identityToken))
		}
		if p.appBearer != "" {
			h.Set(authorizationHeader, bearerValue(p.appBearer))
		}
		if p.appSecret {
			h.Set(c.cfg.ClientSecretHeader, c.cfg.ClientSecret)
		}
	}
}

// identityHeaderValue adds the Bearer scheme only where the header expects
// one. A custom header such as X-Identity-Token usually carries the bare JWT,
// and prefixing it there means the PDP sees a token it cannot parse.
func identityHeaderValue(header, token string) string {
	if strings.EqualFold(header, authorizationHeader) {
		return bearerValue(token)
	}
	return token
}

// identityFingerprint is a short, stable, non-reversible id for a JWT, so that
// repeated denials for one user can be correlated in logs without the token
// itself ever being written down. The token is a credential: logging it hands
// whoever reads the log the ability to act as that user.
func identityFingerprint(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return "jwt:" + hex.EncodeToString(sum[:4])
}

// bearerValue accepts either a bare token or one that already carries its
// scheme, so a caller can forward an Authorization header verbatim.
func bearerValue(token string) string {
	if strings.Contains(token, " ") {
		return token
	}
	return "Bearer " + token
}

// trace logs a payload or response when tracing is on. Payloads are redacted
// first: credentials may travel in a request body, and client code tends to
// log payloads precisely when it is debugging an auth failure.
func (c *Client) trace(msg, requestID string, args ...any) {
	if !c.cfg.EnableTracing {
		return
	}
	c.cfg.Logger.Info(msg, append([]any{"requestId", requestID}, args...)...)
}

// redact replaces the value of every credential-bearing field anywhere in a
// JSON document, at any depth, before it reaches a log line. A body that
// cannot be parsed is dropped entirely rather than logged blind.
func redact(body []byte) json.RawMessage {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return json.RawMessage(`"<unparseable payload, not logged>"`)
	}
	out, err := json.Marshal(redactValue(doc))
	if err != nil {
		return json.RawMessage(`"<unloggable payload>"`)
	}
	return out
}

// secretFields are matched case-insensitively after removing "-" and "_", so
// clientSecret, client_secret and x-client-secret all match one entry.
var secretFields = map[string]bool{
	"clientsecret":   true,
	"xclientsecret":  true,
	"authorization":  true,
	"password":       true,
	"accesstoken":    true,
	"idtoken":        true,
	"refreshtoken":   true,
	"cookie":         true,
	"setcookie":      true,
	"proxyauthorize": true,
}

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if secretFields[normalizeFieldName(k)] {
				out[k] = "<redacted>"
				continue
			}
			out[k] = redactValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redactValue(val)
		}
		return out
	default:
		return v
	}
}

func normalizeFieldName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r != '-' && r != '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// describePDPError renders an error body as one line. The runtime API answers
// errors three ways — a JSON errors array, a JSON object, or bare text such as
// "None of the Identity Templates Matched" — and the text is the part worth
// having in a log line.
func describePDPError(raw []byte) string {
	var parsed struct {
		Errors []struct {
			Code    string `json:"code"`
			Name    string `json:"name"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &parsed); err == nil && len(parsed.Errors) > 0 {
		parts := make([]string, 0, len(parsed.Errors))
		for _, e := range parsed.Errors {
			switch {
			case e.Code != "" && e.Message != "":
				parts = append(parts, e.Code+" "+e.Message)
			case e.Message != "":
				parts = append(parts, e.Message)
			default:
				parts = append(parts, e.Code+e.Name)
			}
		}
		return strings.Join(parts, "; ")
	}
	return truncate(bytes.TrimSpace(raw), 200)
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
