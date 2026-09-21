package plainid

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// A structurally real JWT, so a failure reads like the thing being tested.
const testJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoidGVzdCIsIm5hbWUiOiJKb2huIERvZSIsImNvdW50cnkiOiJVUyJ9." +
	"gdtxqnM6OjzRBo1K5vK_cDvP-umsG4uq_BKav_pZu-w"

func TestJWTIdentityReplacesEntityFields(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	c := v3Client(t, pdp.URL, nil) // EntityTypeID is configured, and must not leak

	if !c.Can(context.Background(), IdentityFromToken(testJWT), "Read", Resource{Type: "Accounts"}) {
		t.Fatal("Can = false")
	}

	p := pdp.payload(t)
	// The PDP resolves the identity from the token. Sending a configured
	// entityTypeId alongside it would override the tenant's own choice of
	// identity template.
	if _, ok := p["entityId"]; ok {
		t.Errorf("entityId must be omitted with a JWT identity: %v", p["entityId"])
	}
	if _, ok := p["entityTypeId"]; ok {
		t.Errorf("entityTypeId must be omitted with a JWT identity: %v", p["entityTypeId"])
	}
	if got := pdp.lastReq.Header.Get("Authorization"); got != "Bearer "+testJWT {
		t.Errorf("Authorization = %q, want the caller's JWT", got)
	}
	// The application still authenticates as itself, with its own credentials.
	if got := pdp.lastReq.Header.Get("X-Client-Secret"); got != "shh" {
		t.Errorf("X-Client-Secret = %q — the JWT identifies the user, not this application", got)
	}
	if got := pdp.lastReq.Header.Get("X-Client-Id"); got != "cid" {
		t.Errorf("X-Client-Id = %q", got)
	}
}

func TestJWTIdentityCarriesExtraAttributes(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	c := v3Client(t, pdp.URL, nil)

	id := IdentityFromToken(testJWT)
	id.Attributes = map[string][]string{"branch_id": {"512"}}
	c.Can(context.Background(), id, "Read", Resource{Type: "Accounts"})

	attrs, ok := pdp.payload(t)["entityAttributes"].(map[string]any)
	if !ok {
		t.Fatalf("entityAttributes missing: %v", pdp.payload(t))
	}
	if _, ok := attrs["branch_id"].([]any); !ok {
		t.Errorf("attributes must still travel with a JWT identity: %#v", attrs)
	}
}

func TestJWTIdentityOnTheTokenAPI(t *testing.T) {
	pdp := newV3Stub(t, tokenPath)
	pdp.body = tokenBody
	c := v3Client(t, pdp.URL, nil)

	perms, err := c.Permissions(context.Background(), IdentityFromToken(testJWT), "Bank Accounts")
	if err != nil {
		t.Fatalf("Permissions: %v", err)
	}
	if !perms.Allows("Bank Accounts", "View") {
		t.Error("token call with a JWT identity returned nothing")
	}
	if _, ok := pdp.payload(t)["entityId"]; ok {
		t.Error("entityId must be omitted with a JWT identity")
	}
	if got := pdp.lastReq.Header.Get("Authorization"); got != "Bearer "+testJWT {
		t.Errorf("Authorization = %q", got)
	}
}

func TestCustomIdentityHeaderCarriesTheBareToken(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	c := v3Client(t, pdp.URL, func(cfg *Config) {
		cfg.IdentityTokenHeader = "X-Identity-Token"
		cfg.ClientSecret = ""
		cfg.AuthMethod = AuthMethodToken
		cfg.BearerToken = "app-token"
	})

	if !c.Can(context.Background(), IdentityFromToken(testJWT), "Read", Resource{Type: "Accounts"}) {
		t.Fatal("Can = false")
	}
	// A custom header usually expects the raw JWT; a Bearer prefix there is a
	// token the PDP cannot parse.
	if got := pdp.lastReq.Header.Get("X-Identity-Token"); got != testJWT {
		t.Errorf("X-Identity-Token = %q, want the bare JWT", got)
	}
	// With the identity moved aside, Authorization is free for the
	// application's own credential.
	if got := pdp.lastReq.Header.Get("Authorization"); got != "Bearer app-token" {
		t.Errorf("Authorization = %q, want this application's token", got)
	}
}

// Two credentials cannot share one header. Rather than silently dropping one —
// which authenticates as nobody and denies everything — this refuses.
func TestConflictingCredentialsRefuse(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	c := v3Client(t, pdp.URL, func(cfg *Config) {
		cfg.ClientSecret = ""
		cfg.AuthMethod = AuthMethodToken
		cfg.BearerToken = "app-token"
	})

	d := c.Check(context.Background(), Ask(IdentityFromToken(testJWT), "Read", Resource{Type: "Accounts"}))
	if d.Permit {
		t.Fatal("a credential conflict must not permit")
	}
	if !strings.Contains(d.Err.Error(), "Authorization") {
		t.Errorf("the error must name the header at fault: %v", d.Err)
	}
	if pdp.calls != 0 {
		t.Errorf("PDP called %d times with credentials that could not be sent", pdp.calls)
	}
}

// With a secret available there is no conflict to report: the application uses
// it, and the JWT keeps the Authorization header.
func TestSecretYieldsTheAuthorizationHeaderToTheIdentity(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	c := v3Client(t, pdp.URL, func(cfg *Config) { cfg.BearerToken = "app-token" })

	if !c.Can(context.Background(), IdentityFromToken(testJWT), "Read", Resource{Type: "Accounts"}) {
		t.Fatal("Can = false")
	}
	if got := pdp.lastReq.Header.Get("Authorization"); got != "Bearer "+testJWT {
		t.Errorf("Authorization = %q, want the caller's JWT", got)
	}
	if pdp.lastReq.Header.Get("X-Client-Secret") != "shh" {
		t.Error("the application must fall back to its secret")
	}
}

// The JWT is a credential: whoever reads the log could act as that user.
func TestJWTIsNeverLogged(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	pdp.body = `{"data":{"result":"DENY"}}`

	var logged bytes.Buffer
	c := v3Client(t, pdp.URL, func(cfg *Config) {
		cfg.Logger = slog.New(slog.NewTextHandler(&logged, nil))
		cfg.EnableTracing = true // the noisiest setting there is
	})

	c.Check(context.Background(), Ask(IdentityFromToken(testJWT), "Read", Resource{Type: "Accounts"}))

	out := logged.String()
	if strings.Contains(out, testJWT) {
		t.Fatalf("the JWT was written to the log:\n%s", out)
	}
	// Something must still identify the caller, or the denial cannot be
	// investigated at all.
	if !strings.Contains(out, identityFingerprint(testJWT)) {
		t.Errorf("no identity fingerprint in the log:\n%s", out)
	}
}

func TestTokenFromAuthorization(t *testing.T) {
	for in, want := range map[string]string{
		"Bearer " + testJWT: testJWT,
		"bearer abc":        "abc",
		"JWT abc":           "abc",
		"abc":               "abc",
		"  Bearer  abc  ":   "abc",
		"":                  "",
		// Not a scheme this strips: hand back what arrived rather than
		// guessing and sending half a credential.
		"Basic dXNlcjpwdw==": "Basic dXNlcjpwdw==",
	} {
		if got := TokenFromAuthorization(in); got != want {
			t.Errorf("TokenFromAuthorization(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJWTIdentityStillFailsClosed(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	pdp.status, pdp.body = 401, `{"error":"bad token"}`
	c := v3Client(t, pdp.URL, nil)

	if c.Can(context.Background(), IdentityFromToken(testJWT), "Read", Resource{Type: "Accounts"}) {
		t.Fatal("a rejected token must deny")
	}
	if c.Can(context.Background(), IdentityFromToken(""), "Read", Resource{Type: "Accounts"}) {
		t.Fatal("an empty identity must deny")
	}
}
