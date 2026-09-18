// Package plainid authorizes HTTP requests against a PlainID PDP (Policy
// Decision Point), mirroring the behaviour of the PlainID API Gateway policy.
//
// It makes exactly one decision call per request, permits only when the PDP
// answers with the exact string "PERMIT", and fails closed on every other
// outcome (outage, timeout, non-200, unparseable response, oversized body).
//
// This package is framework-neutral: it works with plainid.Request, a plain
// description of an inbound call. The web-framework middleware lives
// alongside it, one package per framework:
//
//	middleware/nethttp   net/http, and anything that speaks it (chi,
//	                     gorilla/mux, httputil.ReverseProxy)
//
// To support a framework of your own, translate its request into
// plainid.Request and call Authorizer.AuthorizeRequest; everything about the
// decision — payload shape, fail-closed rules, the uniform denial — stays
// here rather than being reimplemented per framework.
package plainid

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Auth methods.
const (
	// AuthMethodToken forwards the caller's own Authorization header to the
	// PDP; the caller's bearer token identifies them.
	AuthMethodToken = "token"
	// AuthMethodSecret authenticates the gateway itself with client
	// credentials; the caller's identity reaches the PDP through the payload
	// headers instead.
	AuthMethodSecret = "secret"
)

// Defaults mirroring the APIM policy fragment's named values.
const (
	DefaultAuthMethod       = AuthMethodToken
	DefaultRequestTimeout   = 60 * time.Second
	DefaultOnPreventStatus  = http.StatusForbidden
	DefaultOnPreventBody    = `{ "code": 403, "error": "Forbidden" }`
	DefaultOnPreventType    = "application/json"
	DefaultMaxBodyBytes     = 1 << 20 // 1 MiB
	DefaultClientIDHeader   = "X-Client-Id"
	DefaultClientSecretHead = "X-Client-Secret"
	decisionPath            = "/runtime/5.0/decisions/permit-deny"
	requestIDHeader         = "X-Request-ID"
	authorizedByHeader      = "X-Authorized-By"
	authorizedByValue       = "PlainID"
)

// noneLiteral is treated as "not set", so one configuration transfers
// unchanged from APIM (which requires named values to be non-blank).
const noneLiteral = "none"

// Config configures the authorizer. Use ConfigFromEnv to populate it from the
// canonical environment variables, or build it directly.
type Config struct {
	// URL is the PDP base URL, e.g. https://tenant.plainid.io/api. The
	// implementation appends /runtime/5.0/decisions/permit-deny. Required.
	URL string

	// ClientID is the PlainID client id sent on every decision call.
	ClientID string
	// ClientSecret is required when AuthMethod is "secret".
	ClientSecret string

	// AuthMethod is "token" (default) or "secret".
	AuthMethod string

	// ClientIDHeader / ClientSecretHeader name the credential headers.
	// Deployments differ: X-Client-Id/X-Client-Secret and
	// x-plainid-client-id/x-plainid-client-secret are both in use. Confirm
	// against the target tenant. Defaults: X-Client-Id / X-Client-Secret.
	ClientIDHeader     string
	ClientSecretHeader string

	// RuntimeFineTune is sent as meta.runtimeFineTune. Defaults to {}.
	RuntimeFineTune map[string]any

	// HeadersToForward names inbound headers copied onto the PDP call itself
	// (in addition to always being present in the payload's headers field).
	HeadersToForward []string

	// RequestTimeout bounds the whole PDP call. Default 60s; lower it
	// substantially for API volume — a hung PDP call holds a connection and
	// single-digit seconds is usually right.
	RequestTimeout time.Duration

	// OnPreventStatusCode / OnPreventBody / OnPreventContentType define the
	// single response returned for every refusal, whatever its cause.
	OnPreventStatusCode  int
	OnPreventBody        string
	OnPreventContentType string

	// MaxBodyBytes caps the request body included in the decision payload.
	// A larger body is denied. Default 1 MiB.
	MaxBodyBytes int64

	// EnableTracing logs each decision, the payload and the raw PDP response.
	// The payload contains the caller's headers and body — enable it
	// deliberately.
	EnableTracing bool

	// Logger receives decision and failure logs. Defaults to slog.Default().
	Logger *slog.Logger

	// HTTPClient calls the PDP. Defaults to a pooled keep-alive client; reuse
	// of connections matters here, a TLS handshake per request can cost more
	// than the decision itself.
	HTTPClient *http.Client

	// TrustForwardedHeaders resolves ipAddress from X-Forwarded-For and
	// uri.schema from X-Forwarded-Proto. Only enable it when the gateway sits
	// behind a proxy you control — these headers are caller-supplied
	// otherwise.
	TrustForwardedHeaders bool
}

// ConfigFromEnv reads the canonical environment variables:
//
//	PLAINID_URL, PLAINID_CLIENT_ID, PLAINID_CLIENT_SECRET, PLAINID_AUTH_METHOD,
//	PLAINID_RUNTIME_FINE_TUNE, PLAINID_HEADERS_TO_FORWARD,
//	PLAINID_REQUEST_TIMEOUT (seconds), PLAINID_CLIENT_ID_HEADER,
//	PLAINID_CLIENT_SECRET_HEADER, ON_PREVENT_STATUS_CODE, ON_PREVENT_BODY,
//	ON_PREVENT_CONTENT_TYPE, ENABLE_TRACING, MAX_BODY_BYTES,
//	PLAINID_TRUST_FORWARDED_HEADERS
//
// The literal "none" means "not set".
func ConfigFromEnv() (Config, error) {
	c := Config{
		URL:                  env("PLAINID_URL"),
		ClientID:             env("PLAINID_CLIENT_ID"),
		ClientSecret:         env("PLAINID_CLIENT_SECRET"),
		AuthMethod:           env("PLAINID_AUTH_METHOD"),
		ClientIDHeader:       env("PLAINID_CLIENT_ID_HEADER"),
		ClientSecretHeader:   env("PLAINID_CLIENT_SECRET_HEADER"),
		OnPreventBody:        env("ON_PREVENT_BODY"),
		OnPreventContentType: env("ON_PREVENT_CONTENT_TYPE"),
	}

	if v := env("PLAINID_HEADERS_TO_FORWARD"); v != "" {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				c.HeadersToForward = append(c.HeadersToForward, h)
			}
		}
	}
	if v := env("PLAINID_RUNTIME_FINE_TUNE"); v != "" {
		if err := json.Unmarshal([]byte(v), &c.RuntimeFineTune); err != nil {
			return c, fmt.Errorf("PLAINID_RUNTIME_FINE_TUNE is not a JSON object: %w", err)
		}
	}
	if v := env("PLAINID_REQUEST_TIMEOUT"); v != "" {
		secs, err := strconv.ParseFloat(v, 64)
		if err != nil || secs <= 0 {
			return c, fmt.Errorf("PLAINID_REQUEST_TIMEOUT must be a positive number of seconds, got %q", v)
		}
		c.RequestTimeout = time.Duration(secs * float64(time.Second))
	}
	if v := env("ON_PREVENT_STATUS_CODE"); v != "" {
		code, err := strconv.Atoi(v)
		if err != nil || code < 100 || code > 599 {
			return c, fmt.Errorf("ON_PREVENT_STATUS_CODE must be a valid HTTP status, got %q", v)
		}
		c.OnPreventStatusCode = code
	}
	if v := env("MAX_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return c, fmt.Errorf("MAX_BODY_BYTES must be a non-negative integer, got %q", v)
		}
		c.MaxBodyBytes = n
	}
	c.EnableTracing = envBool("ENABLE_TRACING")
	c.TrustForwardedHeaders = envBool("PLAINID_TRUST_FORWARDED_HEADERS")

	return c, nil
}

// env reads a variable, treating the literal "none" as unset.
func env(name string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if strings.EqualFold(v, noneLiteral) {
		return ""
	}
	return v
}

func envBool(name string) bool {
	switch strings.ToLower(env(name)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// normalize fills defaults and validates. It returns a copy, leaving the
// caller's Config untouched.
func (c Config) normalize() (Config, error) {
	if c.URL == "" {
		return c, errors.New("plainid: URL is required")
	}
	c.URL = strings.TrimRight(c.URL, "/")

	switch c.AuthMethod {
	case "":
		c.AuthMethod = DefaultAuthMethod
	case AuthMethodToken, AuthMethodSecret:
	default:
		return c, fmt.Errorf("plainid: AuthMethod must be %q or %q, got %q",
			AuthMethodToken, AuthMethodSecret, c.AuthMethod)
	}
	if c.AuthMethod == AuthMethodSecret && c.ClientSecret == "" {
		return c, errors.New("plainid: ClientSecret is required when AuthMethod is \"secret\"")
	}

	if c.ClientIDHeader == "" {
		c.ClientIDHeader = DefaultClientIDHeader
	}
	if c.ClientSecretHeader == "" {
		c.ClientSecretHeader = DefaultClientSecretHead
	}
	if c.RuntimeFineTune == nil {
		c.RuntimeFineTune = map[string]any{}
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = DefaultRequestTimeout
	}
	if c.OnPreventStatusCode == 0 {
		c.OnPreventStatusCode = DefaultOnPreventStatus
	}
	if c.OnPreventBody == "" {
		c.OnPreventBody = DefaultOnPreventBody
	}
	if c.OnPreventContentType == "" {
		c.OnPreventContentType = DefaultOnPreventType
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.HTTPClient == nil {
		c.HTTPClient = defaultHTTPClient(c.RequestTimeout)
	}
	return c, nil
}
