# Examples

Three show the client inside an application; two show the middleware in front
of one. Each runs on its own port, so several can be up at once.

| Example | Port | The question it answers |
|---|---|---|
| [permit-deny](#permit-deny) | 8081 | May this user do this to this object? |
| [permit-deny-jwt](#permit-deny-jwt) | 8083 | The same, with the caller's JWT as the identity |
| [access-token](#access-token) | 8082 | What may this user do, and to which assets? |
| [simple-server](#simple-server) | 8080 | May this caller make this HTTP request? |
| [reverse-proxy](#reverse-proxy) | 8080 | The same, in front of an upstream |

All read configuration from the environment (see the
[root README](../README.md)).

```bash
export PLAINID_URL=https://<tenant>.plainid.io/api
export PLAINID_CLIENT_ID=<client-id>
export PLAINID_CLIENT_SECRET=<secret>          # the v3 endpoints authenticate
export PLAINID_AUTH_METHOD=secret              # this application, not the caller
export PLAINID_ENTITY_TYPE_ID=<identity-template-id>
```

`PLAINID_ENTITY_TYPE_ID` is the one to get right first. An id that matches no
identity template in your tenant denies everything, and the only symptom is a
blanket deny — set `PLAINID_INCLUDE_DENY_REASON=true` while you are finding it.
The two JWT-based examples do not need it at all: the tenant resolves the
identity from the token.

## permit-deny

The per-call pattern: load a domain object, ask whether this user may do this
to it.

```bash
go run ./examples/permit-deny                           # :8081
curl    -H 'X-User-Id: angela_bell' localhost:8081/accounts/AS-12
curl -X POST -H 'X-User-Id: angela_bell' localhost:8081/accounts/AS-12/approve
curl    -H 'X-User-Id: angela_bell' localhost:8081/accounts
```

The file is mostly an ordinary service. What to read is the `authz` type at the
bottom: two small functions map a domain user onto `plainid.Identity` and a
domain account onto `plainid.Resource`, and nothing above them ever sees
`entityTypeId` or `assetAttributes`. Those two mappings are where nearly every
real bug in a PlainID client lives, which is why they are separated and worth
unit-testing against a recorded payload.

Three shapes, deliberately different:

| Handler | Call | Why |
|---|---|---|
| `GET /accounts/{id}` | `Can` | A bool is all the handler needs. |
| `POST /accounts/{id}/approve` | `Check` | A consequential write, so the refusal gets a log line carrying the request id and whether the PDP answered at all. |
| `GET /accounts` | one `Check` with several resources | One round trip for a page, rather than one per row. |

That last one scales to a page and **not** to a table. When the question is
"which of these ten thousand rows", the answer is the Policy Resolution API,
which pushes the constraint into the query — see the root README.

## permit-deny-jwt

The same service, with the identity mapping deleted. The caller's JWT is
forwarded to the PDP, which resolves who they are from the tenant's identity
template — so no `entityId` and no `entityTypeId` are sent at all.

```bash
export JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoidGVzdCIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjIsImNvdW50cnkiOiJVUyJ9.gdtxqnM6OjzRBo1K5vK_cDvP-umsG4uq_BKav_pZu-w

go run ./examples/permit-deny-jwt                       # :8083
curl    -H "Authorization: Bearer $JWT" localhost:8083/accounts/AS-12
curl -X POST -H "Authorization: Bearer $JWT" localhost:8083/accounts/AS-12/approve
```

`PLAINID_ENTITY_TYPE_ID` is not needed here. `PLAINID_CLIENT_SECRET` is: the
Authorization header now carries the *caller's* identity, so this application
authenticates as itself with its client id and secret. Those are two different
credentials answering two different questions, and the client refuses to send a
call where they would collide in one header — the example checks for it at
startup and says so.

What the PDP actually receives:

```
--> /api/runtime/permit-deny/v3  Authorization: Bearer eyJhbGciOi…
                                 X-Client-Id: cid  X-Client-Secret: •••
    {"entityAttributes":{"channel":["web"]},
     "listOfResources":[{"resourceType":"Accounts","resources":[
       {"action":"Read","path":"AS-12","assetAttributes":{"branch":["San Jose"]}}]}]}
```

No identity fields, and attributes the token does not carry (`channel`) still
travel alongside it. Asset mapping stays yours — only your application knows
what an account is.

Two things this example is deliberate about: it verifies nothing about the
token itself (do that in your own middleware before forwarding — the PDP
resolving an identity is not your service having authenticated the caller), and
it never logs the token. Denials carry a fingerprint instead:

```
WARN plainid: denied requestId=b829afa1… identity=jwt:d62a5303 resources=Accounts:Approve(AS-12) reason="policy denied"
```

## access-token

The User Access Token API: ask what a user may do, and let the answer drive the
application.

```bash
go run ./examples/access-token                          # :8082
curl    -H "Authorization: Bearer $JWT" localhost:8082/my/assets
curl -X POST -H "Authorization: Bearer $JWT" localhost:8082/orders/order1/approve
```

**Nothing in this file tells the PDP what assets exist.** `Permissions` is
called with no asset list and no resource types, so the PDP resolves the assets
from the tenant's own sources and answers with the ones this identity may act
on — each with its attributes and permitted actions, ready to render without a
second lookup. Against a real tenant, `/my/assets` returns:

```json
{"assets":[{"path":"order1","resourceType":"Orders","actions":["Read"],
            "attributes":{"Industry":["Retail"],"name":["order1"],"path":["order1"]}},
           {"path":"order3","resourceType":"Orders","actions":["Read"], …}],
 "readableOrders":["order1","order3"]}
```

`readableOrders` is `perms.PathsFor("Orders", "Read")` — for a bounded
collection, the ids a list endpoint would fetch. Not for an unbounded one: the
token enumerates every allowed asset, and that is Policy Resolution's job.

Two more things the same answer gives you, if the screen wants them:
`perms.Map()` is resource type → actions, which is the shape to hand a front
end — it carries no asset attributes and no permission names, so it leaks less
of your policy structure than the whole token. `perms.ResourceTypes()` is what
a menu can be built from, so a resource type added in PlainID shows up without
a deploy.

`/orders/{id}/approve` is the counterexample: a write is authorized now, with
`Check`, against that specific asset. A token says what to *offer*; it is a
snapshot, and goes stale the moment policy changes.

The example calls the token API per request to keep it to one idea. A real
service fetches it once at session start and holds it — that is what the API is
for.

The caller is identified by whichever arrives: a bearer JWT is forwarded and
the PDP resolves it, otherwise `X-User-Id` is used with the identity template
from `PLAINID_ENTITY_TYPE_ID`.

Failure is a 503, not an empty list. An empty permission map permits nothing,
so answering 200 with one would be indistinguishable from "this user may do
nothing" — a different thing entirely, and the one the caller would act on.

## simple-server

Enforcement in front of a `http.ServeMux`. Handlers run only on PERMIT and do
no permission checking of their own. `/healthz` and `OPTIONS` preflight are
excluded, declared together in one `plainidhttp.WithSkip`.

```bash
go run ./examples/simple-server            # :8080, LISTEN_ADDR to change
curl -i -H "Authorization: Bearer $TOKEN" localhost:8080/api/v1/orders/42
curl -i localhost:8080/healthz             # excluded from enforcement
```

## reverse-proxy

The same middleware wrapping an `httputil.ReverseProxy`, as part of a
middleware chain:

```
request ──▶ requestLogger ──▶ authorize ──▶ proxy ──▶ upstream
              │                 │
              │                 └─ 403 on anything but PERMIT
              └─ logs either outcome: method, path, status, bytes, duration,
                 request id
```

Because the decision happens before the proxy handler runs, a denied request
never opens a connection to the upstream.

Order matters. `requestLogger` wraps `authorize`, so it sees denials as well as
forwarded calls; the other way round it would only ever log permitted traffic —
exactly the requests you least need a record of. Both log lines carry the same
request id:

```
level=WARN msg="plainid: denied" requestId=f7ce603a… method=DELETE path=/api/v1/orders/42 reason="policy denied" result=DENY
level=INFO msg=request method=DELETE path=/api/v1/orders/42 status=403 bytes=37 duration=682µs requestId=f7ce603a… authorized=false
```

`/healthz` is answered locally and deliberately left out of the logger chain
(health checks are log noise); it still passes through `authorize`, where
`plainidhttp.WithSkip` is what lets it by — so exclusions stay declared in one
place.

The logger's `ResponseWriter` wrapper keeps `Flush` and `Hijack`, which a
reverse proxy needs for streaming responses and connection upgrades.

```bash
export UPSTREAM_URL=http://localhost:9000
go run ./examples/reverse-proxy            # :8080
curl -i -H "Authorization: Bearer $TOKEN" localhost:8080/api/v1/orders/42
```

The inbound path, query, body and headers reach the upstream unchanged, plus
`X-Request-ID` and `X-Authorized-By: PlainID`.

Set `PLAINID_TRUST_FORWARDED_HEADERS=true` only when a load balancer you
control sits in front of this proxy and sets `X-Forwarded-For`; otherwise the
caller chooses the address the PDP sees.
