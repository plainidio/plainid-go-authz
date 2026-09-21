// Package plainid is a client for the PlainID Runtime Authorization APIs, for
// Go applications that need to decide what a user may do.
//
// One Client, three questions — pick by what the call site is actually asking:
//
//	Client.Can / Client.Check    may this user do this to this object?
//	                             (permit-deny v3; the per-call workhorse)
//	Client.Permissions           what may this user do at all?
//	                             (user access token; session-scoped)
//	Client.AuthorizeRequest      may this caller make this HTTP request?
//	                             (decisions 5.0; what the middleware uses)
//
// Choosing between them is the decision that matters, because a wrong choice
// is not a bug: the code works, and is either slow or quietly permissive. Use
// Can where a domain object is loaded. Use Permissions at session start, for
// menus and buttons — never to authorize a consequential write, since it is a
// snapshot that goes stale the moment policy changes. Use AuthorizeRequest in
// a route guard, where policy is authored against the HTTP surface.
//
// Every one of them fails closed. A permit requires HTTP 200 and the exact
// string PERMIT; an unreachable PDP, a timeout, a non-200, an unparseable
// body and a missing result are all refusals. The token API's closed answer
// is an empty permission map, which permits nothing.
//
// Call sites speak your application's language; only this package speaks
// PlainID's. Map a domain user onto Identity and a domain object onto
// Resource in one place each — those two mappings are where nearly all real
// bugs live — and entityTypeId, assetAttributes and the rest never leak into
// your handlers.
//
// Where callers already arrive with a JWT, the identity mapping goes away
// entirely: IdentityFromToken forwards the token and the PDP resolves who the
// caller is, so entityId and entityTypeId are neither required nor sent.
//
// The framework middleware lives alongside, one package per framework, and
// uses the same Client:
//
//	middleware/nethttp    net/http, and anything that speaks it (chi,
//	                      gorilla/mux, httputil.ReverseProxy)
//	middleware/fasthttp   fasthttp
//
// To support a framework of your own, translate its request into
// plainid.Request and call Client.AuthorizeRequest; everything about the
// decision — payload shape, fail-closed rules, the uniform denial — stays
// here rather than being reimplemented per framework.
package plainid

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
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

	// DefaultIdentityTokenHeader is where an end user's JWT is sent on the v3
	// endpoints when Identity.Token is set.
	DefaultIdentityTokenHeader = "Authorization"
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

	// AuthMethod is "token" (default) or "secret". It decides how the 5.0
	// request path authenticates: "token" forwards the caller's own
	// Authorization header to the PDP, "secret" authenticates this
	// application with client credentials.
	AuthMethod string

	// BearerToken authenticates this application to the PDP with a token
	// rather than a secret, for the v3 endpoints (Can, Check, Permissions).
	// Per-call overrides live on Query.BearerToken and TokenQuery.BearerToken.
	BearerToken string

	// IdentityTokenHeader names the header carrying the end user's JWT when
	// Identity.Token is set — "Authorization" by default. Change it where the
	// tenant reads the identity from somewhere else, or where this
	// application authenticates itself with a bearer token and the two would
	// otherwise collide.
	IdentityTokenHeader string

	// EntityTypeID is the default identity template id, used whenever an
	// Identity does not carry its own. A wrong value denies everything —
	// confirm it against the tenant before blaming your code.
	EntityTypeID string

	// UseCache is sent as useCache on the v3 endpoints, letting the PDP reuse
	// its own calculation. Nil means true. Turn it off while testing policy
	// changes, or you will debug stale answers.
	//
	// This is the PDP's cache, not a local one. This client keeps no local
	// decision cache: a permit-deny verdict can depend on asset attributes,
	// context, environment and time, so a cache keyed on less than the whole
	// request authorizes the wrong thing.
	UseCache *bool

	// IncludeDetails asks the v3 permit-deny endpoint for the per-resource
	// breakdown (Decision.Allowed / Denied / NotApplicable). Useful in
	// development and in logs; it makes responses much larger, so leaving it
	// on at volume costs real bandwidth.
	IncludeDetails bool

	// IncludeDenyReason asks the PDP why it denied. Invaluable while
	// building. Treat the reason as internal — surfacing it to end users
	// leaks policy structure.
	IncludeDenyReason bool

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

	// missingAPIPrefix records that the base URL carried no path at all, so
	// normalize can say so once at startup rather than per request.
	missingAPIPrefix bool

	// TrustForwardedHeaders resolves ipAddress from X-Forwarded-For and
	// uri.schema from X-Forwarded-Proto. Only enable it when the gateway sits
	// behind a proxy you control — these headers are caller-supplied
	// otherwise.
	TrustForwardedHeaders bool
}

// ConfigFromEnv reads the canonical environment variables:
//
//	PLAINID_URL, PLAINID_CLIENT_ID, PLAINID_CLIENT_SECRET, PLAINID_BEARER_TOKEN,
//	PLAINID_AUTH_METHOD, PLAINID_ENTITY_TYPE_ID, PLAINID_IDENTITY_TOKEN_HEADER,
//	PLAINID_USE_CACHE,
//	PLAINID_INCLUDE_DETAILS, PLAINID_INCLUDE_DENY_REASON,
//	PLAINID_RUNTIME_FINE_TUNE, PLAINID_HEADERS_TO_FORWARD,
//	PLAINID_REQUEST_TIMEOUT (seconds), PLAINID_CLIENT_ID_HEADER,
//	PLAINID_CLIENT_SECRET_HEADER, ON_PREVENT_STATUS_CODE, ON_PREVENT_BODY,
//	ON_PREVENT_CONTENT_TYPE, ENABLE_TRACING, MAX_BODY_BYTES,
//	PLAINID_TRUST_FORWARDED_HEADERS
//
// The literal "none" means "not set". Secrets belong in the environment or a
// secret manager, never in source.
func ConfigFromEnv() (Config, error) {
	c := Config{
		URL:                  env("PLAINID_URL"),
		ClientID:             env("PLAINID_CLIENT_ID"),
		ClientSecret:         env("PLAINID_CLIENT_SECRET"),
		BearerToken:          env("PLAINID_BEARER_TOKEN"),
		AuthMethod:           env("PLAINID_AUTH_METHOD"),
		EntityTypeID:         env("PLAINID_ENTITY_TYPE_ID"),
		IdentityTokenHeader:  env("PLAINID_IDENTITY_TOKEN_HEADER"),
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
	if v := env("PLAINID_USE_CACHE"); v != "" {
		c.UseCache = Bool(envBool("PLAINID_USE_CACHE"))
	}
	c.IncludeDetails = envBool("PLAINID_INCLUDE_DETAILS")
	c.IncludeDenyReason = envBool("PLAINID_INCLUDE_DENY_REASON")
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
	// The base URL is used exactly as given: every runtime path is appended
	// to it verbatim. Guessing a missing /api would break self-hosted
	// deployments that serve the API at the root, so say something instead —
	// a base URL missing /api 404s every call, and a client that fails closed
	// turns that into a blanket deny with nothing in any log to explain it.
	if u, err := url.Parse(c.URL); err != nil || u.Scheme == "" || u.Host == "" {
		return c, fmt.Errorf("plainid: URL must be absolute, got %q", c.URL)
	} else if !strings.HasSuffix(u.Path, "/api") && u.Path == "" {
		c.missingAPIPrefix = true
	}

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
	if c.IdentityTokenHeader == "" {
		c.IdentityTokenHeader = DefaultIdentityTokenHeader
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
	if c.missingAPIPrefix {
		c.Logger.Warn("plainid: base URL has no path; PlainID cloud tenants serve the runtime API under /api",
			"url", c.URL, "hint", c.URL+"/api")
	}
	return c, nil
}

// useCache reports the configured value of the v3 useCache flag, which
// defaults to true: the PDP reusing its own calculation is nearly free, and
// is the first performance lever to reach for.
func (c Config) useCache() bool {
	if c.UseCache == nil {
		return true
	}
	return *c.UseCache
}
