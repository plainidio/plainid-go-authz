# plainid-go-authz

Go middleware that authorizes every HTTP request against a PlainID PDP before
it reaches your backend — the same enforcement the PlainID API Gateway policy
performs, as a Go library.

```
client ──▶ your server ──(permit?)──▶ PlainID PDP
                │ PERMIT                     │ anything else
                ▼                            ▼
            your handler              403 { "code": 403, "error": "Forbidden" }
```

One decision per request, on the request only. Responses are never inspected or
rewritten.

## Packages

The decision logic is framework-neutral; each web framework gets a thin adapter
of its own.

| Import | Package | What it is |
|---|---|---|
| `github.com/plainidio/plainid-go-authz/plainid` | `plainid` | Core: configuration, PDP client, payload, decision. No framework dependency. |
| `github.com/plainidio/plainid-go-authz/middleware/nethttp` | `plainidhttp` | `net/http` middleware — also covers chi, gorilla/mux and `httputil.ReverseProxy`, which all speak `http.Handler`. |

Adapters are named `plainid<framework>` (`plainidhttp`, and `plainidfasthttp`,
`plainidgin` as they arrive) so they never collide with the framework's own
package name at an import site. The package name therefore differs from the
last path segment — alias the import to say so:

```go
import plainidhttp "github.com/plainidio/plainid-go-authz/middleware/nethttp"
```

```
plainid/              core, framework-neutral
middleware/nethttp/   the net/http adapter
internal/authztest/   the contract suite every adapter must pass
examples/             runnable servers
```

## Install

```bash
go get github.com/plainidio/plainid-go-authz/middleware/nethttp
```

Zero dependencies beyond the standard library. Go 1.22+.

## Use

```go
import (
    plainidhttp "github.com/plainidio/plainid-go-authz/middleware/nethttp"
    "github.com/plainidio/plainid-go-authz/plainid"
)

cfg, err := plainid.ConfigFromEnv()   // or build plainid.Config directly
if err != nil {
    log.Fatal(err)
}
cfg.RequestTimeout = 5 * time.Second

authorize, err := plainidhttp.Middleware(cfg, plainidhttp.WithSkip(
    func(r *http.Request) bool { return r.URL.Path == "/healthz" },
))
if err != nil {
    log.Fatal(err)
}

http.ListenAndServe(":8080", authorize(mux))
```

`authorize` wraps any `http.Handler`, including an `httputil.ReverseProxy`, and
composes with other middleware. Put a logger *outside* it so denials are logged
too — see `examples/reverse-proxy`:

```go
mux.Handle("/", chain(proxy, logger, authorize))  // logger → authorize → proxy
```

For enforcement outside a handler chain, hold an `Enforcer` and decide yourself:

```go
e, err := plainidhttp.New(cfg)
// ... inside a handler:
if d := e.Authorize(r); !d.Permit {
    e.WriteDenial(w, d.RequestID)
    return
}
```

`Authorize` behaves exactly as the middleware does, minus writing the response:
it consumes and restores `r.Body` so the request stays forwardable, stamps
`X-Request-ID` whatever the verdict, adds `X-Authorized-By` on permit, and logs
the decision.

## Examples

| Example | What it shows |
|---|---|
| [`examples/simple-server`](examples/simple-server) | `net/http` server; handlers run only on PERMIT |
| [`examples/reverse-proxy`](examples/reverse-proxy) | `httputil.ReverseProxy` behind a middleware chain (logger → authorize → proxy); denied calls never reach the upstream |

```bash
export PLAINID_URL=https://<tenant>.plainid.io/api
export PLAINID_CLIENT_ID=<client-id>
go run ./examples/simple-server
curl -i -H "Authorization: Bearer $TOKEN" localhost:8080/api/v1/orders/42
```

## Configuration

Read from the environment by `ConfigFromEnv`, or set as `Config` fields. The
literal `none` means "not set", so one configuration transfers unchanged from
the APIM policy fragment.

| Variable | Field | Default | Meaning |
|---|---|---|---|
| `PLAINID_URL` | `URL` | *required* | PDP base URL. Often needs an `/api` suffix; `/runtime/5.0/decisions/permit-deny` is appended. |
| `PLAINID_CLIENT_ID` | `ClientID` | — | PlainID client id. |
| `PLAINID_CLIENT_SECRET` | `ClientSecret` | — | Required when the auth method is `secret`. |
| `PLAINID_AUTH_METHOD` | `AuthMethod` | `token` | `token` forwards the caller's `Authorization`; `secret` uses client credentials. |
| `PLAINID_CLIENT_ID_HEADER` | `ClientIDHeader` | `X-Client-Id` | See "Credential headers" below. |
| `PLAINID_CLIENT_SECRET_HEADER` | `ClientSecretHeader` | `X-Client-Secret` | |
| `PLAINID_RUNTIME_FINE_TUNE` | `RuntimeFineTune` | `{}` | JSON object sent as `meta.runtimeFineTune`. |
| `PLAINID_HEADERS_TO_FORWARD` | `HeadersToForward` | — | Comma-separated inbound header names copied onto the PDP call. Not capped at five. |
| `PLAINID_REQUEST_TIMEOUT` | `RequestTimeout` | `60` (seconds) | **Lower this.** See below. |
| `ON_PREVENT_STATUS_CODE` | `OnPreventStatusCode` | `403` | Status on any refusal. |
| `ON_PREVENT_BODY` | `OnPreventBody` | `{ "code": 403, "error": "Forbidden" }` | Body on any refusal. |
| `ON_PREVENT_CONTENT_TYPE` | `OnPreventContentType` | `application/json` | Content type of that body. |
| `ENABLE_TRACING` | `EnableTracing` | `false` | Log each decision, payload and raw PDP response. The payload contains caller headers and body. |
| `MAX_BODY_BYTES` | `MaxBodyBytes` | `1048576` | Largest body included in the payload; larger is **denied**. |
| `PLAINID_TRUST_FORWARDED_HEADERS` | `TrustForwardedHeaders` | `false` | Resolve `ipAddress` from `X-Forwarded-For` and `uri.schema` from `X-Forwarded-Proto`. |

Fields with no variable: `Logger` (a `*slog.Logger`) and `HTTPClient`.
Route exclusions are per-framework, so they are an adapter option
(`plainidhttp.WithSkip`) rather than core configuration.

Configuration is validated once at construction, so a bad timeout or auth
method fails at startup rather than at request time.

### Credential headers

`X-Client-Id`/`X-Client-Secret` and
`x-plainid-client-id`/`x-plainid-client-secret` are both in use across
deployments — these are different names, not a casing difference. Confirm
against your tenant; getting it wrong authenticates as nobody and surfaces as a
blanket deny. Override with `ClientIDHeader`/`ClientSecretHeader`.

## Behaviour

**Fails closed.** A request is forwarded only when the PDP answers HTTP 200
with `data.result` exactly `"PERMIT"`. Everything else is a refusal: PDP
unreachable, timeout, any non-200, unparseable response, missing or different
result, a body over `MaxBodyBytes`.

> The operational consequence is real: **if the PDP is unreachable, the API
> stops serving.** That argues for PDP redundancy and a tight timeout, not for
> failing open.

**The denial is uniform.** Policy denials and PDP outages produce the identical
response, so a caller cannot tell them apart or probe which paths exist. The
distinction is recorded in the logs instead — verdict, reason, raw error,
request id, caller address.

**Permitted requests reach the backend byte-identical**, except for two
headers: `X-Request-ID` (the caller's, or a generated UUID) and
`X-Authorized-By: PlainID`. The middleware does not inject claims or rewrite
paths; that belongs in its own component.

**Request correlation.** `X-Request-ID` is kept if the caller sent one — the
lookup is case-insensitive, so `x-request-id` is not duplicated — sent to the
PDP, echoed on the denial, and forwarded on permit. It is usually the only way
to answer "why was this call denied" afterwards.

It is also stamped onto the inbound `r.Header` whatever the verdict, so an
outer middleware such as a request logger can correlate a *denied* request with
the PDP audit record. A generated id is never added to the decision payload's
`headers`, which carry only what the caller sent.

**One decision per request.** No retries: a retry turns one slow call into
several.

### Exclusions

Nothing is excluded unless you pass `plainidhttp.WithSkip`. Both examples exclude `/healthz`
(liveness must answer while the PDP is down) and the server example also
excludes `OPTIONS` (CORS preflight carries no caller identity). Keep every
exclusion explicit and documented — an undocumented exclusion is
indistinguishable from a bypass.

### Performance

This runs on every request, so:

- **The PDP client pools connections** (`MaxIdleConnsPerHost` 64, keep-alive).
  A fresh TLS handshake per request can cost more than the decision.
- **Lower `PLAINID_REQUEST_TIMEOUT`.** The documented default of 60s is a
  policy-tool default and dangerous at API volume — hung calls pile up and
  exhaust the connection pool. Single-digit seconds is usually right; both
  examples use 5s.
- **Bodies are read up to `MAX_BODY_BYTES`** and then replayed to the backend,
  so uploads are not buffered without limit. Over the limit is a deny, by
  deliberate choice.
- **No decision cache is provided.** A decision can depend on body, query and
  headers, so a cache keyed on anything less authorizes the wrong request. If
  you add one, key it on the full payload, keep the TTL short, and prefer
  caching denials over permits.

## The decision payload

Built per request and POSTed to `{PLAINID_URL}/runtime/5.0/decisions/permit-deny`:

```json
{
  "ipAddress": "203.0.113.7",
  "method": "POST",
  "uri": {
    "path": ["/api/v1/orders/42", "api", "v1", "orders", "42"],
    "query": {"expand": "items"},
    "schema": "https"
  },
  "headers": {"authorization": ["Bearer ..."], "x-tenant": ["acme"]},
  "requestId": "3f9c…",
  "authenticationMethod": "token",
  "meta": {"runtimeFineTune": {}},
  "body": {"amount": 12.5}
}
```

Notes that matter when debugging a blanket deny:

- `uri.path` is the **full path at index 0**, then its `/`-split segments, with
  no empty entry for the leading slash — so segment N sits at index N.
  Policies are authored against this shape: they match either the whole path at
  index 0 or a segment at a known index, and a mismatch denies everything with
  no error anywhere.
- `uri.schema` — that spelling, not `scheme`.
- Header names are lower-cased and each value is split on commas.
- `body` is parsed JSON when it parses, the raw string otherwise. An
  unparseable body is not a denial: the operation is identified by method and
  URI.
- `ipAddress` is the direct peer unless `TrustForwardedHeaders` is on.

Common symptoms:

| Symptom | Usual cause |
|---|---|
| `RT-087 None of the Identity Templates Matched` | The bearer token's identity maps to no identity template in the tenant. |
| 401/403 from the PDP with no policy detail | Wrong credential header names, or a base URL missing `/api`. |
| 200 with `DENY` for everything | Policy resource scope does not match what is being sent. |

## Adding another framework

An adapter translates its framework's request into `plainid.Request` and calls
`AuthorizeRequest`. Nothing about the decision — payload shape, fail-closed
rules, the uniform denial — is reimplemented:

```go
req := plainid.Request{
    Method:     string(ctx.Method()),
    Path:       string(ctx.Path()),
    Query:      query,          // one value per key
    Header:     header,         // any casing; the core lower-cases it
    Scheme:     scheme,
    RemoteAddr: ctx.RemoteAddr().String(),
    Body:       body,           // already read, and size-capped
}

d := authorizer.AuthorizeRequest(ctx, req)
if !d.Permit {
    authorizer.LogDenial(req, d)
    // write authorizer.Denial() the way this framework expects
    return
}
```

Core helpers an adapter needs: `ReadCappedBody` (for streamed bodies),
`RequestID`, `Denial`, `LogDenial`, `LogPermit`, and the
`RequestIDHeader`/`AuthorizedByHeader` constants.

Conventions for a new adapter:

- directory `middleware/<framework>`, package `plainid<framework>`;
- a framework with heavy dependencies (fasthttp, gin, echo) gets **its own
  `go.mod`**, tagged as `middleware/<framework>/vX.Y.Z`, so `net/http` users do
  not inherit them;
- it must pass the shared contract suite (below) before it ships.

Frameworks that compose `func(http.Handler) http.Handler` — chi, gorilla/mux,
`httputil.ReverseProxy` — need no adapter at all; use `middleware/nethttp`.

## Tests

```bash
go test ./...
```

`internal/authztest` holds the acceptance suite every adapter must pass, plus
the stub PDP and backend recorder that drive it. Wiring a new adapter into it
is a few lines:

```go
gw := authztest.Gateway{URL: srv.URL, PDP: pdp, Backend: backend}
authztest.RunContract(t, gw)

gw.PDP.Stop()
authztest.RunFailsClosed(t, gw)   // with the PDP down, everything must be refused
```

It checks per-identity verdicts, method and path sensitivity, the payload's
wire shape, denial uniformity, request-id correlation, one decision per
request, declared exclusions, that permitted requests reach the backend
unmodified, and that denied ones never reach it at all. Alongside it, unit
tests cover the payload construction and every fail-closed path.

The library was also verified end to end with the gateway-agnostic acceptance
suite (`verify_enforcement.py`) driving `examples/reverse-proxy` against a stub
PDP: 13/13 checks passed, the backend's own log showed only the permitted
calls, and with the PDP stopped every request was refused.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
