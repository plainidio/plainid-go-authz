// Command permit-deny-jwt shows the same per-call authorization as
// examples/permit-deny, with one difference that removes most of the code:
// the caller's JWT is forwarded to the PDP, and the PDP resolves who they are.
//
//	go run ./examples/permit-deny-jwt
//	curl -H "Authorization: Bearer $JWT" localhost:8083/accounts/AS-12
//	curl -X POST -H "Authorization: Bearer $JWT" localhost:8083/accounts/AS-12/approve
//
// There is no identity mapping in this file. No entityId, no entityTypeId, no
// function turning a domain user into a PlainID identity — the tenant's
// identity template decides which claim identifies the user, so that decision
// lives in one place rather than being duplicated in every service that calls
// the PDP. Asset mapping is still yours, because only your application knows
// what an account is.
//
// What you give up: the PDP sees whatever claims the token carries. If a
// policy needs an attribute that is not in the token, pass it in
// Identity.Attributes — as `region` is below — or model it as an identity
// source in the tenant.
package main

import (
	"encoding/json"
	"errors"
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
	cfg.IncludeDenyReason = true

	// The caller's JWT travels in Authorization, so this application
	// authenticates itself with its client id and secret. Those are two
	// different credentials answering two different questions — who is asking,
	// and on behalf of whom — and the client refuses to start a call where
	// they would collide in one header.
	if cfg.ClientSecret == "" {
		log.Fatal("PLAINID_CLIENT_SECRET is required: the Authorization header carries the caller's identity, " +
			"so this application cannot also authenticate with a bearer token there " +
			"(or set PLAINID_IDENTITY_TOKEN_HEADER to move the identity elsewhere)")
	}

	client, err := plainid.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	app := &app{client: client, log: slog.Default()}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /accounts/{id}", app.readAccount)
	mux.HandleFunc("POST /accounts/{id}/approve", app.approveAccount)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	addr := envOr("LISTEN_ADDR", ":8083")
	slog.Info("listening", "addr", addr, "identityHeader", client.Config().IdentityTokenHeader)
	log.Fatal(http.ListenAndServe(addr, mux))
}

type app struct {
	client *plainid.Client
	log    *slog.Logger
}

func (a *app) readAccount(w http.ResponseWriter, r *http.Request) {
	identity, ok := caller(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	account, err := loadAccount(r.PathValue("id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if !a.client.Can(r.Context(), identity, "Read", resource(account)) {
		deny(w)
		return
	}
	writeJSON(w, account)
}

func (a *app) approveAccount(w http.ResponseWriter, r *http.Request) {
	identity, ok := caller(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	account, err := loadAccount(r.PathValue("id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	d := a.client.Check(r.Context(), plainid.Ask(identity, "Approve", resource(account)))
	if !d.Permit {
		// There is no user id to log here, and the token must never be
		// written to a log — it is a credential. The client logs a stable
		// fingerprint of it instead, and this line carries the request id,
		// which is what ties the refusal to the PDP's audit record.
		a.log.Warn("approval refused",
			"account", account.ID, "requestId", d.RequestID,
			"outage", d.Failed(), "reason", d.Reason)
		deny(w)
		return
	}
	writeJSON(w, map[string]string{"status": "approved", "account": account.ID})
}

// caller describes who is asking, using nothing but the token they arrived
// with. This replaces the whole identity-mapping layer of the sibling example.
//
// Verify the token here, in your own middleware, before forwarding it. The PDP
// resolving an identity from a token is not the same as your service having
// authenticated the caller: a policy decision about an unverified token is a
// decision about a claim anyone could have written.
func caller(r *http.Request) (plainid.Identity, bool) {
	token := plainid.TokenFromAuthorization(r.Header.Get("Authorization"))
	if token == "" {
		return plainid.Identity{}, false
	}
	identity := plainid.IdentityFromToken(token)

	// Attributes the token does not carry can still travel alongside it.
	// Arrays, always.
	identity.Attributes = map[string][]string{"channel": {"web"}}
	return identity, true
}

// resource maps a domain object onto a PlainID asset. Still yours: only this
// application knows what an account is.
func resource(a account) plainid.Resource {
	return plainid.Resource{
		Type: "Accounts",
		Path: a.ID,
		Attributes: map[string][]string{
			"branch":       {a.Branch},
			"account_type": {a.Type},
		},
	}
}

type account struct {
	ID     string `json:"id"`
	Branch string `json:"branch"`
	Type   string `json:"type"`
}

func loadAccount(id string) (account, error) {
	for _, a := range []account{
		{ID: "AS-12", Branch: "San Jose", Type: "private"},
		{ID: "AS-13", Branch: "Portland", Type: "business"},
	} {
		if a.ID == id {
			return a, nil
		}
	}
	return account{}, errors.New("no such account")
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
