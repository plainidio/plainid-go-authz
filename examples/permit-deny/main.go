// Command permit-deny shows the per-call authorization pattern: a service
// loads a domain object and asks the PDP whether this user may do this to it.
//
//	go run ./examples/permit-deny
//	curl -H 'X-User-Id: angela_bell' localhost:8081/accounts/AS-12
//	curl -X POST -H 'X-User-Id: angela_bell' localhost:8081/accounts/AS-12/approve
//	curl -H 'X-User-Id: angela_bell' localhost:8081/accounts
//
// The point of the file is the authz type at the bottom: it is the only place
// that knows what entityTypeId or assetAttributes are. Handlers ask
// "may this user read this account?" and get a bool.
package main

import (
	"context"
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
	// The documented default of 60s is a policy-tool default. This call sits
	// in the request path, so single digits is right: a hung PDP call
	// otherwise holds a request goroutine until the pool is exhausted.
	cfg.RequestTimeout = 5 * time.Second
	// While building, ask the PDP to explain itself. Log the reason; never
	// return it — it describes your policy structure.
	cfg.IncludeDenyReason = true
	cfg.IncludeDetails = true

	client, err := plainid.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	app := &app{authz: &authz{client: client}, log: slog.Default()}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /accounts/{id}", app.readAccount)
	mux.HandleFunc("POST /accounts/{id}/approve", app.approveAccount)
	mux.HandleFunc("GET /accounts", app.listAccounts)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	addr := envOr("LISTEN_ADDR", ":8081")
	slog.Info("listening", "addr", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

type app struct {
	authz *authz
	log   *slog.Logger
}

// readAccount is the shape almost every handler takes: load the object,
// ask about the object, then use it.
func (a *app) readAccount(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	account, err := loadAccount(r.PathValue("id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// The whole authorization decision, in the application's own vocabulary.
	if !a.authz.Can(r.Context(), user, "Read", account) {
		deny(w)
		return
	}
	writeJSON(w, account)
}

// approveAccount is a consequential write, so it asks the PDP now rather than
// trusting anything cached from session start. See the access-token example
// for the other half of that argument.
func (a *app) approveAccount(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	account, err := loadAccount(r.PathValue("id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Check, not Can, where the outcome is worth a log line of its own: it
	// carries the request id that ties this refusal to the PDP's audit
	// record, and says whether policy denied or the PDP never answered.
	d := a.authz.Check(r.Context(), user, "Approve", account)
	if !d.Permit {
		a.log.Warn("approval refused",
			"user", user.ID, "account", account.ID,
			"requestId", d.RequestID, "outage", d.Failed(), "reason", d.Reason)
		deny(w)
		return
	}
	writeJSON(w, map[string]string{"status": "approved", "account": account.ID})
}

// listAccounts asks about several accounts in one call rather than looping
// Can, which would be one PDP round trip per row.
//
// This scales to a page, not to a table. When the question is "which of these
// ten thousand rows may they see", neither Can nor a batch is the answer:
// that is what the Policy Resolution API is for, and it pushes the constraint
// into the query instead of filtering after the database already returned
// rows the user may not see.
func (a *app) listAccounts(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	page := accountPage()

	d := a.authz.CanEach(r.Context(), user, "Read", page)
	visible := make([]account, 0, len(page))
	for _, acc := range page {
		if d.Allows(accountsResourceType, "Read", acc.ID) {
			visible = append(visible, acc)
		}
	}
	a.log.Info("listed accounts",
		"user", user.ID, "requestId", d.RequestID, "of", len(page), "visible", len(visible))
	writeJSON(w, visible)
}

// ---------------------------------------------------------------------------
// The mapping layer. Everything PlainID-shaped lives here and nowhere else, so
// that changing the identity template or the asset model is one edit rather
// than a codebase-wide search.
// ---------------------------------------------------------------------------

const accountsResourceType = "Accounts"

type authz struct {
	client *plainid.Client
}

// identity maps a domain user onto a PlainID identity. Note entityId is the
// uid the identity template keys on — not necessarily your primary key. Get
// this wrong and everything denies with no error anywhere, so it is worth a
// unit test against a recorded payload.
func (a *authz) identity(u user) plainid.Identity {
	return plainid.Identity{
		ID: u.ID,
		// TypeID comes from PLAINID_ENTITY_TYPE_ID; set it per identity here
		// if one service authorizes several kinds of caller.
		Attributes: map[string][]string{
			// Attribute values are arrays. Always. A bare string does not
			// error — it fails to match, and you get a silent deny.
			"user_organization": {u.Org},
			"user_title":        {u.Title},
		},
	}
}

// resource maps a domain object onto a PlainID asset.
func (a *authz) resource(acc account) plainid.Resource {
	return plainid.Resource{
		Type: accountsResourceType,
		Path: acc.ID,
		Attributes: map[string][]string{
			"branch":       {acc.Branch},
			"account_type": {acc.Type},
		},
	}
}

// Can is what handlers call. It fails closed: an unreachable PDP, a timeout,
// a non-200, an unparseable body and any result other than PERMIT all
// return false.
func (a *authz) Can(ctx context.Context, u user, action string, acc account) bool {
	return a.client.Can(ctx, a.identity(u), action, a.resource(acc))
}

// Check is Can with the reason, for the paths worth logging in detail.
func (a *authz) Check(ctx context.Context, u user, action string, acc account) plainid.Decision {
	return a.client.Check(ctx, plainid.Ask(a.identity(u), action, a.resource(acc)))
}

// CanEach asks about a page of accounts in one call. Details are required for
// the per-resource breakdown; without them the answer is one verdict for the
// whole request.
func (a *authz) CanEach(ctx context.Context, u user, action string, accs []account) plainid.Decision {
	q := plainid.Query{
		Identity:       a.identity(u),
		IncludeDetails: plainid.Bool(true),
	}
	for _, acc := range accs {
		res := a.resource(acc)
		res.Action = action
		q.Resources = append(q.Resources, res)
	}
	return a.client.Check(ctx, q)
}

// ---------------------------------------------------------------------------
// Stand-ins for the parts of your application that are not about PlainID.
// ---------------------------------------------------------------------------

type user struct {
	ID    string
	Org   string
	Title string
}

type account struct {
	ID     string `json:"id"`
	Branch string `json:"branch"`
	Type   string `json:"type"`
}

// currentUser stands in for your authentication. In a real service this comes
// from a verified token or session, never from a header the caller controls.
func currentUser(r *http.Request) (user, bool) {
	id := r.Header.Get("X-User-Id")
	if id == "" {
		return user{}, false
	}
	return user{ID: id, Org: "Acme Finance", Title: "Branch Clerk"}, true
}

func loadAccount(id string) (account, error) {
	for _, a := range accountPage() {
		if a.ID == id {
			return a, nil
		}
	}
	return account{}, errors.New("no such account")
}

func accountPage() []account {
	return []account{
		{ID: "AS-12", Branch: "San Jose", Type: "private"},
		{ID: "AS-13", Branch: "Portland", Type: "business"},
		{ID: "AS-14", Branch: "San Jose", Type: "business"},
	}
}

// deny answers every refusal identically, whatever caused it. A caller who
// can tell a policy denial from a PDP outage can map your policies; the
// distinction belongs in the logs, which is where the client puts it.
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
