package plainid

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// Responses recorded verbatim from a live PlainID tenant
// (demo.preprod.plainid.io, runtime v3). They differ from the published
// examples in ways that decide whether this library works at all, so they are
// kept exactly as they arrived.
const (
	// Discovery: no assetList and no resourceTypes were sent. The PDP
	// resolved the assets itself and returned them with their attributes.
	recordedDiscovery = `{"tokenValidity":0,"response":[{"access":[` +
		`{"path":"order1","attributes":{"Industry":["Retail"],"name":["order1"],"path":["order1"]},"resourceType":"Orders","actions":[{"action":"Read"}]},` +
		`{"path":"order3","attributes":{"Industry":["Retail"],"name":["order3"],"path":["order3"]},"resourceType":"Orders","actions":[{"action":"Read"}]}` +
		`]}],"contextData":null}`

	// Permit/deny, this tenant: no data envelope.
	recordedPermit = `{"result":"PERMIT","response":[{"allowed":[{"path":"order1","action":"Read","template":"Orders"}],"denied":[],"not_applicable":[]}]}`
	recordedDeny   = `{"result":"DENY","reason":["PID005"],"response":[{"allowed":[],"denied":[{"path":"order2","action":"Read","template":"Orders","reason":"PID005"}],"not_applicable":[]}]}`
	recordedBatch  = `{"result":"DENY","response":[{"allowed":[{"path":"order1","action":"Read","template":"Orders"}],"denied":[{"path":"order2","action":"Read","template":"Orders"}],"not_applicable":[]}]}`

	// Errors, as the runtime API actually returns them: a JSON array on the
	// 5.0 endpoint, and bare text on v3.
	recordedErrorsArray = `{"errors":[{"id":"E56G7L","code":"RT-087","name":"InvalidParameter","message":"None of the Identity Templates Matched"}]}`
	recordedErrorText   = `None of the Identity Templates Matched`
)

// The published examples wrap the verdict in a data envelope; this tenant does
// not. A client that reads only one shape denies every request and logs
// nothing to explain it, so both must work.
func TestBothPermitDenyResponseShapes(t *testing.T) {
	for name, body := range map[string]string{
		"documented envelope": `{"data":{"result":"PERMIT"}}`,
		"tenant top level":    recordedPermit,
		"envelope with details": `{"data":{"result":"PERMIT","response":[{"allowed":` +
			`[{"path":"order1","action":"Read","template":"Orders"}],"denied":[],"not_applicable":[]}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			pdp := newV3Stub(t, permitDenyPath)
			pdp.body = body
			c := v3Client(t, pdp.URL, nil)

			d := c.Check(context.Background(), Ask(testUser, "Read", Resource{Type: "Orders", Path: "order1"}))
			if !d.Permit {
				t.Fatalf("Permit = false for the %s shape: %+v", name, d)
			}
			if strings.Contains(name, "details") || name == "tenant top level" {
				if !d.Allows("Orders", "Read", "order1") {
					t.Errorf("details not read from the %s shape: %+v", name, d.Allowed)
				}
			}
		})
	}
}

func TestRecordedDenyCarriesItsReason(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	pdp.body = recordedDeny
	c := v3Client(t, pdp.URL, func(cfg *Config) { cfg.IncludeDenyReason = true })

	d := c.Check(context.Background(), Ask(testUser, "Read", Resource{Type: "Orders", Path: "order2"}))
	if d.Permit {
		t.Fatal("DENY permitted")
	}
	// The field is "reason" and holds an array of policy codes, not the
	// singular "denyReason" string the documentation shows.
	if d.DenyReason != "PID005" {
		t.Errorf("DenyReason = %q, want PID005", d.DenyReason)
	}
	if len(d.Denied) != 1 || d.Denied[0].Reason != "PID005" {
		t.Errorf("per-resource reason missing: %+v", d.Denied)
	}
	if !d.DeniedByPolicy() || d.Failed() {
		t.Error("a real verdict must not look like a PDP failure")
	}
}

// A batch answers one verdict for the whole request; the breakdown says which
// resource failed. Filtering on the overall verdict alone hides every
// permitted row behind one denied one.
func TestRecordedBatchSplitsAllowedFromDenied(t *testing.T) {
	pdp := newV3Stub(t, permitDenyPath)
	pdp.body = recordedBatch
	c := v3Client(t, pdp.URL, nil)

	d := c.Check(context.Background(), Query{
		Identity:       testUser,
		IncludeDetails: Bool(true),
		Resources: []Resource{
			{Type: "Orders", Action: "Read", Path: "order1"},
			{Type: "Orders", Action: "Read", Path: "order2"},
		},
	})
	if d.Permit {
		t.Error("a batch with one denial must not report an overall permit")
	}
	if !d.Allows("Orders", "Read", "order1") || d.Allows("Orders", "Read", "order2") {
		t.Errorf("breakdown wrong: allowed=%+v denied=%+v", d.Allowed, d.Denied)
	}
}

// The identity template not matching is the most common first-run failure.
// "PDP returned status 403" alone sends people to read their own code; the
// answer is in the body.
func TestPDPErrorsReachTheLog(t *testing.T) {
	for name, body := range map[string]string{
		"errors array": recordedErrorsArray,
		"bare text":    recordedErrorText,
	} {
		t.Run(name, func(t *testing.T) {
			pdp := newV3Stub(t, permitDenyPath)
			pdp.status, pdp.body = 403, body
			c := v3Client(t, pdp.URL, nil)

			d := c.Check(context.Background(), Ask(testUser, "Read", Resource{Type: "Orders"}))
			if d.Permit {
				t.Fatal("an error must deny")
			}
			if !strings.Contains(d.Reason, "None of the Identity Templates Matched") {
				t.Errorf("Reason = %q, want the PDP's own message", d.Reason)
			}
			if !d.Failed() {
				t.Error("a PDP error is not a policy denial")
			}
		})
	}
}

// The feature this is all for: ask for nothing, and the PDP returns the assets
// it resolved from the tenant's own sources.
func TestRecordedDiscovery(t *testing.T) {
	pdp := newV3Stub(t, tokenPath)
	pdp.body = recordedDiscovery
	c := v3Client(t, pdp.URL, nil)

	perms, err := c.Permissions(context.Background(), IdentityFromToken(testJWT))
	if err != nil {
		t.Fatalf("Permissions: %v", err)
	}

	// Neither an asset list nor resource types were sent: the application does
	// not have to know what exists in order to find out what it may touch.
	p := pdp.payload(t)
	if _, ok := p["assetList"]; ok {
		t.Errorf("assetList must be omitted on a discovery call: %v", p["assetList"])
	}
	if _, ok := p["resourceTypes"]; ok {
		t.Errorf("resourceTypes must be omitted on a discovery call: %v", p["resourceTypes"])
	}

	if got := perms.PathsFor("Orders", "Read"); !reflect.DeepEqual(got, []string{"order1", "order3"}) {
		t.Errorf("PathsFor = %v, want the assets the PDP resolved", got)
	}
	if got := perms.PathsFor("Orders", "Delete"); len(got) != 0 {
		t.Errorf("PathsFor(Delete) = %v, want none", got)
	}
	assets := perms.Assets("Orders")
	if len(assets) != 2 {
		t.Fatalf("Assets = %+v", assets)
	}
	// Attributes come back resolved from the tenant's sources, which is what
	// makes the list renderable without a second lookup.
	if got := assets[0].Attribute("Industry"); !reflect.DeepEqual(got, []string{"Retail"}) {
		t.Errorf("Attribute(Industry) = %v", got)
	}
	if !assets[0].Allows("read") || assets[0].Allows("delete") {
		t.Error("Access.Allows is wrong")
	}
	if got := perms.Map(); !reflect.DeepEqual(got, map[string][]string{"Orders": {"Read"}}) {
		t.Errorf("Map = %v", got)
	}
	// Actions carried no permission name here; that field is often absent.
	if perms.Access[0].Actions[0].Permission != "" {
		t.Error("recorded fixture drifted")
	}
	if string(perms.ContextData) != "null" {
		t.Errorf("ContextData = %q", perms.ContextData)
	}
}
