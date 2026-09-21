// Command access-token shows the User Access Token API: ask the PDP what a
// user may do, and let the answer drive the application.
//
//	go run ./examples/access-token
//	curl -H "Authorization: Bearer $JWT" localhost:8082/my/permissions
//	curl -H "Authorization: Bearer $JWT" localhost:8082/my/assets
//	curl -X POST -H "Authorization: Bearer $JWT" localhost:8082/orders/order1/approve
//
// Nothing here tells the PDP what assets exist. The call asks for no asset
// list and no resource types, so the PDP resolves the assets from the tenant's
// own sources and answers with the ones this identity may act on, each
// carrying its attributes and permitted actions.
//
// This example calls the token API per request, to keep it to one idea. A real
// service fetches it once at session start and holds it — that is what the API
// is for — and then treats it as a snapshot: right for what the UI offers,
// wrong for what the service allows. The approve handler shows the difference.
package main

import (
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/plainidio/plainid-go-authz/plainid"
)

func main() {
	cfg, err := plainid.ConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	cfg.RequestTimeout = 5 * time.Second

	client, err := plainid.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	app := &app{client: client}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /my/assets", app.assets)
	mux.HandleFunc("POST /orders/{id}/approve", app.approve)

	addr := envOr("LISTEN_ADDR", ":8082")
	slog.Info("listening", "addr", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

type app struct {
	client *plainid.Client
}

// assets is what discovery buys you: the actual objects this user may act on,
// with the attributes the PDP resolved, ready to render without a second
// lookup.
func (a *app) assets(w http.ResponseWriter, r *http.Request) {
	perms, ok := a.permissionsFor(w, r)
	if !ok {
		return
	}

	type asset struct {
		Path         string              `json:"path"`
		ResourceType string              `json:"resourceType"`
		Actions      []string            `json:"actions"`
		Attributes   map[string][]string `json:"attributes"`
	}
	out := []asset{}
	for _, entitlement := range perms.Assets("") {
		actions := make([]string, 0, len(entitlement.Actions))
		for _, act := range entitlement.Actions {
			actions = append(actions, act.Action)
		}
		out = append(out, asset{
			Path:         entitlement.Path,
			ResourceType: entitlement.ResourceType,
			Actions:      actions,
			Attributes:   entitlement.Attributes,
		})
	}

	writeJSON(w, map[string]any{
		"assets": out,
		// The ids a list endpoint would fetch. For a bounded collection this
		// goes straight into the query; for an unbounded one it does not —
		// the token enumerates every allowed asset, and a million-row table
		// is Policy Resolution's job, which returns the constraint instead.
		"readableOrders": perms.PathsFor("Orders", "Read"),
	})
}

// approve is the counterexample. A token says what to *offer*; a write is
// authorized now, against this specific asset, with Check.
func (a *app) approve(w http.ResponseWriter, r *http.Request) {
	identity, ok := caller(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	orderID := r.PathValue("id")

	d := a.client.Check(r.Context(), plainid.Ask(identity, "Approve", plainid.Resource{
		Type: "Orders",
		Path: orderID,
	}))
	if !d.Permit {
		slog.Warn("approval refused",
			"order", orderID, "requestId", d.RequestID,
			"outage", d.Failed(), "reason", d.Reason)
		deny(w)
		return
	}
	writeJSON(w, map[string]string{"status": "approved", "order": orderID})
}

// permissionsFor makes the one call this example is about: no asset list, no
// resource types, so the PDP answers with everything it resolved.
//
// On failure it returns empty permissions and an error. Empty permits nothing,
// so answering 200 with an empty map would be indistinguishable from "this
// user may do nothing" — which is why this says the service is unavailable
// instead.
func (a *app) permissionsFor(w http.ResponseWriter, r *http.Request) (plainid.Permissions, bool) {
	identity, ok := caller(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return plainid.Permissions{}, false
	}
	perms, err := a.client.Permissions(r.Context(), identity)
	if err != nil {
		slog.Error("could not fetch entitlements", "error", err)
		http.Error(w, "authorization service unavailable", http.StatusServiceUnavailable)
		return plainid.Permissions{}, false
	}
	return perms, true
}

// caller identifies who is asking. A bearer JWT is forwarded and the PDP
// resolves the identity from it; otherwise X-User-Id is used with the
// identity template from PLAINID_ENTITY_TYPE_ID.
//
// Your authentication goes here: verify the token before forwarding it. The
// PDP resolving an identity is not the same as this service having
// authenticated the caller.
func caller(r *http.Request) (plainid.Identity, bool) {
	if token := plainid.TokenFromAuthorization(r.Header.Get("Authorization")); token != "" {
		return plainid.IdentityFromToken(token), true
	}
	if id := r.Header.Get("X-User-Id"); id != "" {
		return plainid.Identity{ID: id}, true
	}
	return plainid.Identity{}, false
}

func deny(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"code":403,"error":"Forbidden"}`))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
