# Examples

Both read configuration from the environment (see the [root README](../README.md)).

```bash
export PLAINID_URL=https://<tenant>.plainid.io/api
export PLAINID_CLIENT_ID=<client-id>
# export PLAINID_AUTH_METHOD=secret PLAINID_CLIENT_SECRET=<secret>
```

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
