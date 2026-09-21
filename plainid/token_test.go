package plainid

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

const tokenBody = `{
  "tokenValidity": 300,
  "response": [{
    "access": [
      {"path":"27iX3j","resourceType":"Bank Accounts",
       "attributes":{"Account Branch":["San Jose"]},
       "actions":[{"action":"View","permission":"Manage accounts","permissionId":"p1"},
                  {"action":"Edit","permission":"Manage accounts","permissionId":"p1"}]},
      {"path":"88zQ","resourceType":"Orders",
       "actions":[{"action":"view","permission":"Read orders","permissionId":"p2"}]}
    ]
  }],
  "identity": {"typeName":"User"}
}`

func TestPermissions(t *testing.T) {
	pdp := newV3Stub(t, tokenPath)
	pdp.body = tokenBody
	c := v3Client(t, pdp.URL, nil)

	p, err := c.Permissions(context.Background(), testUser, "Bank Accounts", "Orders")
	if err != nil {
		t.Fatalf("Permissions: %v", err)
	}

	// The token API answers with a top-level response array and no data
	// envelope. Reading data.result here would find nothing.
	if p.Validity != 300 || len(p.Access) != 2 {
		t.Fatalf("parsed = %+v", p)
	}
	if !p.Allows("Bank Accounts", "View") || !p.Allows("Bank Accounts", "Edit") {
		t.Error("Allows missed a permitted action")
	}
	// Tenants are not consistent about case; PlainID's own examples mix it.
	if !p.Allows("orders", "VIEW") {
		t.Error("Allows must be case-insensitive")
	}
	if p.Allows("Bank Accounts", "Delete") || p.Allows("Reports", "View") {
		t.Error("Allows permitted something the token does not carry")
	}
	if !p.AllowsPath("Bank Accounts", "27iX3j", "View") || p.AllowsPath("Bank Accounts", "other", "View") {
		t.Error("AllowsPath ignored the asset path")
	}
	if got := p.Actions("Bank Accounts"); !reflect.DeepEqual(got, []string{"Edit", "View"}) {
		t.Errorf("Actions = %v", got)
	}
	if got := p.ResourceTypes(); !reflect.DeepEqual(got, []string{"Bank Accounts", "Orders"}) {
		t.Errorf("ResourceTypes = %v", got)
	}
	if got := p.Paths("Orders"); !reflect.DeepEqual(got, []string{"88zQ"}) {
		t.Errorf("Paths = %v", got)
	}
	if got := p.Map(); !reflect.DeepEqual(got, map[string][]string{
		"Bank Accounts": {"Edit", "View"}, "Orders": {"view"},
	}) {
		t.Errorf("Map = %v", got)
	}

	payload := pdp.payload(t)
	if payload["accessTokenFormat"] != TokenFormatJSON {
		t.Errorf("accessTokenFormat = %v", payload["accessTokenFormat"])
	}
	types := payload["resourceTypes"].([]any)
	if len(types) != 2 || types[0].(map[string]any)["name"] != "Bank Accounts" {
		t.Errorf("resourceTypes = %v", types)
	}
}

func TestAccessTokenNarrowsToAssets(t *testing.T) {
	pdp := newV3Stub(t, tokenPath)
	pdp.body = tokenBody
	c := v3Client(t, pdp.URL, nil)

	_, err := c.AccessToken(context.Background(), TokenQuery{
		Identity: testUser,
		Assets: []Asset{{
			Template:   "Orders",
			Path:       "/orders",
			Attributes: map[string][]string{"order_type": {"credit card"}},
		}},
		ResourceTypes: []ResourceTypeQuery{{
			Name: "Bank Accounts", Attributes: []string{"price"}, Actions: []string{"view"},
		}},
	})
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	p := pdp.payload(t)
	asset := p["assetList"].([]any)[0].(map[string]any)
	if asset["template"] != "Orders" || asset["path"] != "/orders" {
		t.Errorf("assetList = %v", asset)
	}
	if _, ok := asset["assetAttributes"].(map[string]any)["order_type"].([]any); !ok {
		t.Errorf("assetAttributes must hold arrays: %v", asset["assetAttributes"])
	}
	rt := p["resourceTypes"].([]any)[0].(map[string]any)
	if len(rt["attributeList"].([]any)) != 1 || len(rt["actions"].([]any)) != 1 {
		t.Errorf("resourceTypes = %v — ask for what the screen needs, not the catalogue", rt)
	}
}

// For the token API, failing closed means an empty permission map: the
// dangerous shape is a client that returns emptiness on error and a caller
// that reads emptiness as "no restrictions".
func TestPermissionsFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"unauthorized", 401, `{"error":"bad credentials"}`},
		{"server error", 500, `oops`},
		{"unparseable", 200, `not json`},
		{"permit-deny-shaped answer", 200, `{"data":{"result":"PERMIT"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pdp := newV3Stub(t, tokenPath)
			pdp.status, pdp.body = tc.status, tc.body
			c := v3Client(t, pdp.URL, nil)

			p, err := c.Permissions(context.Background(), testUser, "Accounts")
			if !p.IsEmpty() || p.Allows("Accounts", "View") {
				t.Fatalf("a failed token call must permit nothing, got %+v", p)
			}
			if tc.status == 200 && tc.name == "permit-deny-shaped answer" {
				return // parses, but carries no access: empty, and no error
			}
			if err == nil {
				t.Fatal("the caller must be told the difference between 'may do nothing' and 'could not ask'")
			}
			if !errors.Is(err, ErrPDPUnavailable) {
				t.Errorf("err does not wrap ErrPDPUnavailable: %v", err)
			}
		})
	}
}

func TestZeroPermissionsPermitNothing(t *testing.T) {
	var p Permissions
	if !p.IsEmpty() || p.Allows("anything", "at all") || len(p.Map()) != 0 {
		t.Fatal("the zero Permissions must permit nothing — that is what makes an ignored error safe")
	}
}

func TestPermissionsDeniesWhenPDPIsUnreachable(t *testing.T) {
	pdp := newV3Stub(t, tokenPath)
	url := pdp.URL
	pdp.Close()

	c := v3Client(t, url, func(cfg *Config) { cfg.RequestTimeout = time.Second })
	p, err := c.Permissions(context.Background(), testUser, "Accounts")
	if err == nil || !p.IsEmpty() {
		t.Fatalf("unreachable PDP: err = %v, permissions = %+v", err, p)
	}
}

func TestAccessTokenRejectsIncompleteQueries(t *testing.T) {
	pdp := newV3Stub(t, tokenPath)
	c := v3Client(t, pdp.URL, nil)

	cases := map[string]TokenQuery{
		"no identity":       {},
		"no asset template": {Identity: testUser, Assets: []Asset{{Path: "/x"}}},
		"no resource name":  {Identity: testUser, ResourceTypes: []ResourceTypeQuery{{}}},
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := c.AccessToken(context.Background(), q); err == nil {
				t.Fatal("want an error")
			}
		})
	}
	if pdp.calls != 0 {
		t.Errorf("PDP called %d times for queries that never should have been sent", pdp.calls)
	}
}

func TestTokenFormat(t *testing.T) {
	for in, want := range map[string]string{
		"": TokenFormatJSON, "json": TokenFormatJSON, "JWT": TokenFormatJWT,
		"standardjwt": TokenFormatStandardJWT, "Something": "Something",
	} {
		if got := tokenFormat(in); got != want {
			t.Errorf("tokenFormat(%q) = %q, want %q", in, got, want)
		}
	}
}
