// Command simple-server is a net/http API server whose routes are authorized
// by the PlainID middleware before any handler runs.
//
//	export PLAINID_URL=https://tenant.plainid.io/api
//	export PLAINID_CLIENT_ID=...
//	export PLAINID_AUTH_METHOD=token
//	go run ./examples/simple-server
//
//	curl -i -H 'Authorization: Bearer <token>' localhost:8080/api/v1/orders/42
package main

import (
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	plainidhttp "github.com/plainidio/plainid-go-authz/middleware/nethttp"
	"github.com/plainidio/plainid-go-authz/plainid"
)

func main() {
	cfg, err := plainid.ConfigFromEnv()
	if err != nil {
		log.Fatalf("configuration: %v", err)
	}

	// 60s is the documented default and far too long for API volume: a hung
	// PDP call holds a connection for a minute. Single-digit seconds is right
	// for in-line enforcement.
	if os.Getenv("PLAINID_REQUEST_TIMEOUT") == "" {
		cfg.RequestTimeout = 5 * time.Second
	}

	cfg.Logger = slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Routes excluded from enforcement. Every exclusion is a hole, so it is
	// listed here explicitly rather than implied by a path prefix:
	//   /healthz  — liveness, must answer while the PDP is down
	//   OPTIONS   — CORS preflight carries no caller identity
	skip := plainidhttp.WithSkip(func(r *http.Request) bool {
		return r.URL.Path == "/healthz" || r.Method == http.MethodOptions
	})

	authorize, err := plainidhttp.Middleware(cfg, skip)
	if err != nil {
		log.Fatalf("plainid middleware: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/api/v1/orders/", showOrder)
	mux.HandleFunc("/api/v1/orders", listOrders)

	srv := &http.Server{
		Addr:              listenAddr(),
		Handler:           authorize(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("listening on %s, authorizing against %s", srv.Addr, cfg.URL)
	log.Fatal(srv.ListenAndServe())
}

// The handlers below never check permissions themselves: by the time they run,
// the PDP has already permitted the call. X-Authorized-By tells them a decision
// was made rather than leaving them to assume one.

func listOrders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"orders":       []map[string]any{{"id": "42", "amount": 12.5}},
		"authorizedBy": r.Header.Get(plainid.AuthorizedByHeader),
		"requestId":    r.Header.Get(plainid.RequestIDHeader),
	})
}

func showOrder(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/orders/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, map[string]any{
		"id":        id,
		"amount":    12.5,
		"requestId": r.Header.Get(plainid.RequestIDHeader),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func listenAddr() string {
	if addr := os.Getenv("LISTEN_ADDR"); addr != "" {
		return addr
	}
	return ":8080"
}
