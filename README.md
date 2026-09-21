# plainid-go-authz

A PlainID authorization client for Go applications, plus the HTTP middleware
built on it. One `plainid.Client`, three questions:

```
                                  ┌──────────────────────────────────────┐
your route guard ────────────────▶│                                      │
  "may this caller make           │                                      │
   this HTTP request?"            │            plainid.Client            │
                                  │                                      │──▶ PlainID PDP
your handler ────────────────────▶│  config · auth · pooled transport    │
  "may this user Read             │  fail-closed parsing · logging       │
   this account?"                 │                                      │
                                  │                                      │
your login ──────────────────────▶│                                      │
  "what may this user do?"        └──────────────────────────────────────┘
```

| Your question | Method | API |
|---|---|---|
| May this user do *this* to *this object*? | `Can` / `Check` | Permit/Deny v3 |
| …identified by the JWT they arrived with | `IdentityFromToken` | Permit/Deny v3 |
| What may this user do at all, on which assets? | `Permissions` | User Access Token v3 |
| May this caller make *this HTTP request*? | `AuthorizeRequest`, or the middleware | Decisions 5.0 |

**Choosing between them is the decision that matters**, because a wrong choice
is not a bug — the code works, and is either slow or quietly permissive:

- `Can` where a domain object is loaded: an account fetched by id, a record
  reached through several routes, a job or a message consumer with no HTTP
  surface at all.
- `Permissions` at session start, to render a menu or enable buttons. Asked
  with no asset list, it also *discovers* which assets exist and which the user
  may touch, resolved by the PDP from the tenant's sources. It is a
  **snapshot**, and goes stale the moment policy or user attributes change —
  never authorize a consequential write from it.
- The middleware in a route guard, where policy is authored against the HTTP
  surface. The request *is* the payload, so there is no per-route mapping to
  write or keep in sync.
- Filtering a list of any size is **none of these**. One permit call per row
  collapses at ten thousand rows, and fetching everything and filtering in
  memory means the database already returned data the user may not see. That
  is the Policy Resolution API's job, and it is not implemented here yet — see
  [Not implemented](#not-implemented).

Everything fails closed, and the middleware makes one decision per request, on
the request only. Responses are never inspected or rewritten.

## Packages

The client is framework-neutral; each web framework gets a thin adapter of its
own, and all of them hold the same `plainid.Client`.

| Import | Package | What it is |
|---|---|---|
| `github.com/plainidio/plainid-go-authz/plainid` | `plainid` | The client: configuration, transport, all three APIs, payloads, decisions. No framework dependency. |
| `github.com/plainidio/plainid-go-authz/middleware/nethttp` | `plainidhttp` | `net/http` middleware — also covers chi, gorilla/mux and `httputil.ReverseProxy`, which all speak `http.Handler`. |
| `github.com/plainidio/plainid-go-authz/middleware/fasthttp` | `plainidfasthttp` | `fasthttp` middleware. **A separate Go module**, so `net/http` users never inherit the fasthttp dependency. |

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
middleware/fasthttp/  the fasthttp adapter — its own go.mod
internal/authztest/   the contract suite every adapter must pass
examples/             runnable servers
```

## Install

```bash
go get github.com/plainidio/plainid-go-authz/middleware/nethttp    # net/http, chi, …
go get github.com/plainidio/plainid-go-authz/middleware/fasthttp   # fasthttp
```

The core and the `net/http` adapter have **zero dependencies beyond the
standard library**; only the fasthttp module pulls anything in, and only for
projects that ask for it. Go 1.22+.

## Use — in your application code

The client is the thing to create once per process and share: configuration is
validated at construction, connections to the PDP are pooled, and both the
domain-level checks and the route guard go through it.

```go
cfg, err := plainid.ConfigFromEnv()
if err != nil {
    log.Fatal(err)
}
cfg.RequestTimeout = 5 * time.Second

client, err := plainid.New(cfg)
```

### May this user do this? — `Can`

```go
ok := client.Can(ctx, user, "Read", account)
```

…where `user` and `account` come from **your** mapping layer — the one place in
your codebase that knows PlainID's vocabulary:

```go
func identity(u User) plainid.Identity {
    return plainid.Identity{
        ID: u.UID,                        // as the identity template expects it
        Attributes: map[string][]string{  // arrays, always
            "user_organization": {u.Org},
        },
    }
}

func resource(a Account) plainid.Resource {
    return plainid.Resource{
        Type:       "Accounts",
        Path:       a.ID,
        Attributes: map[string][]string{"branch": {a.Branch}},
    }
}
```

Keeping that mapping in one small, unit-tested place is the single most
valuable thing this library does for you. `entityTypeId` and `assetAttributes`
are the PDP's words: once they appear at call sites, every change to identity
mapping or asset modelling becomes a codebase-wide edit, and authorization
logic ends up smeared across handlers where nobody can audit it.

### Or skip the mapping: send the caller's JWT

Where your service already authenticates callers with a JWT, forward it and let
the PDP resolve who they are. `entityId` and `entityTypeId` are then neither
required nor sent — the tenant's identity template decides which claim
identifies the user:

```go
identity := plainid.IdentityFromToken(
    plainid.TokenFromAuthorization(r.Header.Get("Authorization")))

ok := client.Can(ctx, identity, "Read", account)
```

That is the whole identity layer. The token goes in
`Config.IdentityTokenHeader` (`Authorization` by default, and sent bare rather
than `Bearer`-prefixed on a custom header), and **this application still
authenticates as itself** with `X-Client-Id` / `X-Client-Secret` — two
credentials answering two different questions. Attributes the token does not
carry can travel alongside it in `Identity.Attributes`.

Two things worth being deliberate about:

- **Verify the token in your own middleware before forwarding it.** The PDP
  resolving an identity from a token is not the same as your service having
  authenticated the caller; a decision about an unverified token is a decision
  about a claim anyone could have written.
- **The Authorization header can only carry one credential.** If the identity
  JWT is there and the only application credential available is a bearer token,
  the client refuses the call with an error rather than dropping one silently —
  which would authenticate as nobody and deny everything. Use a client secret,
  or move the identity to another header with
  `PLAINID_IDENTITY_TOKEN_HEADER`.

The JWT is never logged. Refusals carry a short stable fingerprint of it
(`identity=jwt:d62a5303`) instead, which is enough to correlate repeated
denials for one caller without handing whoever reads the log the ability to act
as them.

The same applies to `Permissions`: pass an `IdentityFromToken` and the token
call resolves the identity the same way.

`Can` returns a bool and never an error — every failure is a `false`. When you
need to know *why*, or to log it, use `Check`:

```go
d := client.Check(ctx, plainid.Ask(identity(u), "Approve", resource(a)))
if !d.Permit {
    log.Warn("refused",
        "requestId", d.RequestID,   // ties this to the PDP's audit record
        "outage", d.Failed(),       // PDP never answered, vs. policy said no
        "reason", d.Reason)
}
```

Several resources in one call, rather than a loop:

```go
d := client.Check(ctx, plainid.Query{
    Identity:       identity(u),
    Resources:      []plainid.Resource{{Type: "Accounts", Action: "Read", Path: "A1"}, …},
    IncludeDetails: plainid.Bool(true),   // needed for the per-resource breakdown
})
d.Allows("Accounts", "Read", "A1")
```

That is right for a page of results and wrong for a table — see
[Not implemented](#not-implemented).

### What may this user do? — `Permissions`

One call at session start, for menus, buttons and a client-side permission map.
**Ask for nothing and the PDP answers with everything**: it resolves the asset
list from the tenant's own sources (the PIP) and returns each asset this
identity may act on, with its attributes and permitted actions. Your
application never has to know, or send, what exists:

```go
perms, err := client.Permissions(ctx, identity)   // no asset list, no resource types

perms.ResourceTypes()                 // → ["Orders"]           — discovered
perms.Assets("Orders")                // → the allowed assets, with attributes
perms.PathsFor("Orders", "Read")      // → ["order1", "order3"] — the ids
perms.Map()                           // → {"Orders": ["Read"]} — for a front end
```

Each entitlement carries what the PDP resolved, so a list is renderable without
a second lookup:

```go
for _, a := range perms.Assets("Orders") {
    a.Path                      // "order1"
    a.Attribute("Industry")     // ["Retail"]
    a.Allows("Read")            // true
}
```

`PathsFor` is the practical one: for a bounded collection those ids go straight
into the query that fetches the rows. It does not scale to an unbounded one —
the token enumerates every allowed asset, so a million-row table produces a
million-entry token. That is Policy Resolution's job, and it returns the
constraint rather than the list.

Narrow with resource type names — `Permissions(ctx, identity, "Orders")` — only
when a screen genuinely needs a subset. One counter-intuitive detail, observed
against a live tenant: **naming a resource type without also listing its
attributes returns fewer asset attributes than asking for everything does.** If
you narrow and still want attributes, list them in
`ResourceTypeQuery.Attributes` via `AccessToken`.

Comparisons are case-insensitive, because tenants are not consistent about
case. `Map()` is what to hand a front end: it carries no asset attributes and
no permission names, so it leaks less of your policy structure than the whole
token.

> **A token is a snapshot.** It is correct for what the UI *offers* and wrong
> for what the service *allows*: entitlements fetched at login are authorized
> against the policy as it was at login. Gate buttons with it; gate the
> approval itself with `Can`. `examples/access-token` does exactly that, in
> one handler.

On failure you get empty `Permissions` **and** an error. Empty permits
nothing — including from the zero value — so a caller that drops the error
still fails closed. Log it anyway: "may do nothing" and "we could not ask" are
different incidents.

## Use — as HTTP middleware

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

### Both patterns in one service

Most services need both: the middleware guards routes, and handlers ask about
the specific object they just loaded. `Enforcer.Client()` hands you the same
client the middleware is using, so there is one configuration, one connection
pool and one set of fail-closed rules rather than two:

```go
e, err := plainidhttp.New(cfg, skip)
mux.Handle("/", e.Handler(routes))

// inside a handler, having loaded the account:
if !e.Client().Can(r.Context(), identity(u), "Approve", resource(account)) {
    e.WriteDenial(w, r.Header.Get(plainid.RequestIDHeader))
    return
}
```

## Examples

| Example | What it shows |
|---|---|
| [`examples/permit-deny`](examples/permit-deny) | `Can` / `Check` per handler, the mapping layer in one place, and a batch check for a page of rows |
| [`examples/permit-deny-jwt`](examples/permit-deny-jwt) | the same, with the caller's JWT forwarded as the identity — no identity mapping at all |
| [`examples/access-token`](examples/access-token) | `Permissions` asked with no asset list: the PDP discovers the assets, and a write still re-checks with `Check` rather than trusting the answer |
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
| `PLAINID_URL` | `URL` | *required* | PDP base URL, used verbatim — the runtime path is appended to it. Cloud tenants serve the API under `/api`, so this usually ends in `/api`; a base URL with no path at all logs a warning at startup, because the alternative is a 404 on every call that fails closed into a blanket deny. |
| `PLAINID_CLIENT_ID` | `ClientID` | — | The Scope's client id. |
| `PLAINID_CLIENT_SECRET` | `ClientSecret` | — | The Scope's secret. Required when the auth method is `secret`. |
| `PLAINID_BEARER_TOKEN` | `BearerToken` | — | Authenticates this application with a token instead of a secret, on the v3 endpoints. Overridable per call with `Query.BearerToken`. |
| `PLAINID_AUTH_METHOD` | `AuthMethod` | `token` | How the **5.0 request path** authenticates: `token` forwards the caller's `Authorization`; `secret` uses client credentials. The v3 endpoints always authenticate this application. |
| `PLAINID_ENTITY_TYPE_ID` | `EntityTypeID` | — | Default identity template id, overridable per call with `Identity.TypeID`. A wrong value denies everything. Not used, and not sent, when `Identity.Token` carries a JWT. |
| `PLAINID_IDENTITY_TOKEN_HEADER` | `IdentityTokenHeader` | `Authorization` | Header carrying the **end user's** JWT when `Identity.Token` is set. On `Authorization` the token is `Bearer`-prefixed; on any other header it is sent bare. |
| `PLAINID_USE_CACHE` | `UseCache` | `true` | Sent as `useCache` on the v3 endpoints, letting the PDP reuse its own calculation. Turn it off while testing policy changes. |
| `PLAINID_INCLUDE_DETAILS` | `IncludeDetails` | `false` | Ask for the per-resource breakdown (`Decision.Allowed` / `Denied` / `NotApplicable`). Much larger responses. |
| `PLAINID_INCLUDE_DENY_REASON` | `IncludeDenyReason` | `false` | Ask the PDP why it denied. On in development; log-only in production — it describes your policy structure. |
| `PLAINID_CLIENT_ID_HEADER` | `ClientIDHeader` | `X-Client-Id` | See "Credential headers" below. |
| `PLAINID_CLIENT_SECRET_HEADER` | `ClientSecretHeader` | `X-Client-Secret` | |
| `PLAINID_RUNTIME_FINE_TUNE` | `RuntimeFineTune` | `{}` | JSON object sent as `meta.runtimeFineTune`. |
| `PLAINID_HEADERS_TO_FORWARD` | `HeadersToForward` | — | Comma-separated inbound header names copied onto the PDP call. Not capped at five. |
| `PLAINID_REQUEST_TIMEOUT` | `RequestTimeout` | `60` (seconds) | **Lower this.** See below. |
| `ON_PREVENT_STATUS_CODE` | `OnPreventStatusCode` | `403` | Status on any refusal. |
| `ON_PREVENT_BODY` | `OnPreventBody` | `{ "code": 403, "error": "Forbidden" }` | Body on any refusal. |
| `ON_PREVENT_CONTENT_TYPE` | `OnPreventContentType` | `application/json` | Content type of that body. |
| `ENABLE_TRACING` | `EnableTracing` | `false` | Log each decision, payload and raw PDP response. Credential-bearing fields (`clientSecret`, `authorization`, cookies, tokens) are redacted at any depth before logging, but the payload still carries caller headers and request bodies — enable it deliberately. |
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

**Fails closed.** A permit requires HTTP 200 and `data.result` exactly
`"PERMIT"`. Everything else is a refusal: PDP unreachable, timeout, any
non-200, unparseable response, missing or different result, a body over
`MaxBodyBytes`. No error path anywhere in this library returns a permit.

For the token API, failing closed means **empty permissions**, which permit
nothing — including from the zero `Permissions` value, so a caller who ignores
the error is still safe. The dangerous shape this avoids is a client that
returns an empty result on error and a caller that reads empty as
"unrestricted".

> The operational consequence is real: **if the PDP is unreachable, the feature
> stops working.** That argues for PDP redundancy and a tight timeout, not for
> failing open.

**Outages and denials stay distinguishable in your logs**, even though they are
indistinguishable to the caller. `Decision.Failed()` reports that the PDP never
answered; `Decision.DeniedByPolicy()` reports a real verdict; every refusal
`Err` wraps `plainid.ErrPDPUnavailable`. With details requested,
`Decision.NoPolicyMatched()` separates a third case: no policy addressed the
resource at all. That is a policy *modelling* gap, it reads exactly like a
denial from the caller's side, and without this it gets debugged as a code bug.

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

**One decision per request.** No retries anywhere: retrying a timeout turns one
slow call into several and can take down the service the authorization was
protecting.

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
- **`useCache` is on by default** for the v3 endpoints. That is the *PDP's*
  cache reusing its own calculation — nearly free, and the first lever to
  reach for. Turn it off while testing policy changes, or you will debug stale
  answers.
- **No local decision cache is provided.** A permit-deny verdict can depend on
  body, query, headers, asset attributes, context, environment and time, so a
  cache keyed on anything less authorizes the wrong thing. If you add one, key
  it on the full payload, keep the TTL in seconds, prefer caching denials over
  permits, and work out invalidation on policy and attribute change before you
  ship it — that is the part that gets forgotten.
- **A session's `Permissions` is the exception**, and caching it per session is
  what it is for. Hold it as a snapshot with a stated lifetime (`Validity`),
  and re-ask for anything consequential.

## The wire formats

Every runtime call is a `POST` with a JSON body, including the ones some
reference pages render as `GET`: identity and asset data in a query string
lands in access logs, proxy caches and browser history, and a large request
gets truncated by an intermediary instead of failing cleanly.

| Method | Endpoint | Result read from |
|---|---|---|
| `AuthorizeRequest` | `{URL}/runtime/5.0/decisions/permit-deny` | `data.result` **or** top-level `result` |
| `Can` / `Check` | `{URL}/runtime/permit-deny/v3` | `data.result` **or** top-level `result` |
| `Permissions` | `{URL}/runtime/token/v3` | top-level `response[]`, no result at all |

Two things this table encodes, both learned by calling a real tenant rather
than reading the docs:

- **The permit-deny envelope is not guaranteed.** The documentation shows
  `{"data":{"result":"PERMIT"}}`; the tenant this was verified against answers
  `{"result":"PERMIT","response":[…]}` with no envelope at all. A client that
  reads only one shape finds nothing in the other and **denies every request,
  with no error anywhere to explain it**. This client reads whichever arrived.
- **The token API is different again** — a top-level `response[]` carrying no
  result. Copying a reader between the two permits or denies everything,
  depending on direction.

### Deny reasons and errors

With `IncludeDenyReason`, the observed field is `reason` and it holds an array
of policy codes, not the singular string the documentation shows; both are
read, and the per-resource code lands on `ResourceRef.Reason`:

```
reason="policy denied" denyReason="PID005" denied=[{Path:order2 Action:Read Template:Orders Reason:PID005}]
```

PDP *errors* arrive three ways — a JSON `errors[]` array, a JSON object, or
bare text — and all of them are non-200. The message is lifted into the refusal
reason, because "PDP returned status 403" on its own sends people to read their
own code when the answer is sitting in the response:

```
reason="PDP returned status 403: None of the Identity Templates Matched" failure=true
```

### The 5.0 decision payload

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

  > **Divergence worth knowing about.** PlainID's API documentation shows this
  > array *keeping* the empty segment the leading slash produces
  > (`["/a/b", "", "a", "b"]`), which shifts every segment index by one. This
  > library sends the shape above, without it. If your policies match on a
  > segment index and deny everything, this is the first thing to check —
  > compare a real payload against a policy that works.
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

d := client.AuthorizeRequest(ctx, req)
if !d.Permit {
    client.LogDenial(req, d)
    // write client.Denial() the way this framework expects
    return
}
```

Expose the client from your `Enforcer` too (`Client()`), so handlers behind the
middleware can ask `Can` and `Permissions` without a second connection pool.

Core helpers an adapter needs: `ReadCappedBody` (for streamed bodies),
`RequestID`, `Denial`, `LogDenial`, `LogPermit`, and the
`RequestIDHeader`/`AuthorizedByHeader` constants.

`middleware/fasthttp` is the worked example: about 200 lines, none of them
about policy. Copy its shape.

Conventions for a new adapter:

- directory `middleware/<framework>`, package `plainid<framework>`;
- a framework with heavy dependencies (fasthttp, gin, echo) gets **its own
  `go.mod`**, tagged as `middleware/<framework>/vX.Y.Z`, so `net/http` users do
  not inherit them;
- it must pass the shared contract suite (below) before it ships.

Frameworks that compose `func(http.Handler) http.Handler` — chi, gorilla/mux,
`httputil.ReverseProxy` — need no adapter at all; use `middleware/nethttp`.

Two details worth copying rather than rediscovering:

- **Send the path as it arrived.** fasthttp's `ctx.Path()` is already
  normalized and percent-decoded, so the adapter uses `URI().PathOriginal()`
  to match what `net/http` sends. Policies must judge the caller's path, not
  the framework's idea of it.
- **The body limit still applies** even when the framework hands you the body
  in memory: `AuthorizeRequest` enforces `MaxBodyBytes` itself, so an adapter
  cannot forget it.

## Tests

```bash
go test ./...                              # core, net/http adapter, examples
cd middleware/fasthttp && go test ./...     # the nested module has its own
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

New-surface unit tests sit beside them: `permitdeny_test.go` and `token_test.go`
cover the identity and asset mapping against recorded payloads (arrays where
arrays belong, resource grouping, the right `entityTypeId`), both response
shapes, and every failure path — timeout, 500, 401, malformed JSON, missing
field, unexpected result string, and each API given the *other* API's response
body. Those failure tests are the security of this library.

Both adapters pass the identical suite — that is the point of it. The fasthttp
module consumes `internal/authztest` across the module boundary and builds
against the *published* core, so its tests also prove the released core is
genuinely reusable.

The library was also verified end to end with the gateway-agnostic acceptance
suite (`verify_enforcement.py`) driving `examples/reverse-proxy` against a stub
PDP: 13/13 checks passed, the backend's own log showed only the permitted
calls, and with the PDP stopped every request was refused.

## Not implemented

Stated rather than left to be discovered:

- **Policy Resolution** (`/runtime/resolution/v3`), the data-filtering API. It
  returns the constraints under which access is allowed, as a nested
  `OR`/`AND` tree, so you can push them into the query that fetches the data.
  That is what makes row-level authorization scale, and it is the right answer
  whenever a call site would otherwise loop `Can` over a collection. Translating
  the filter tree into a query language is real work with three rules that must
  hold — translate the whole tree or refuse, bind values as parameters, and
  treat an empty `allowed` set as *no rows* rather than all rows — so it is
  deliberately absent rather than half-done.
- **User List** (`/runtime/userlist/v3`) and **Policy List**
  (`/runtime/policies/v3`): the reverse lookup ("who can access this?") and
  batch evaluation.
- **No automated integration test against a live tenant.** The suite runs
  against stubs, but the fixtures in `plainid/recorded_test.go` are responses
  recorded verbatim from a real tenant (`demo.preprod.plainid.io`), including
  its un-enveloped verdicts, its `reason` array and a discovery answer. The
  client was also driven against that tenant end to end: discovery, `Can`,
  a denial with its reason, and an unresolvable identity. Re-run that check
  against your own tenant before trusting a deployment — most first-run
  failures are an `entityTypeId` matching no identity template, which denies
  everything.

## Versioning

`plainid.Authorizer` is now an alias for `plainid.Client`, and
`Enforcer.Authorizer()` for `Enforcer.Client()`; both are deprecated but keep
existing code compiling. The `middleware/fasthttp` module carries a `replace`
directive onto the working tree while the new core is unreleased — drop it and
bump its `require` once the core is tagged.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
