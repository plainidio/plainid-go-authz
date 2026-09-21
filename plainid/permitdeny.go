package plainid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Identity is the user (or service, or agent) a decision is about.
//
// This is one half of the mapping that keeps PlainID's vocabulary out of your
// application: one place in your code turns a domain user into an Identity,
// and call sites never see entityId or entityTypeId. Nearly every real bug in
// a client library lives in that mapping, so keep it small, named and
// unit-tested.
type Identity struct {
	// Token is the end user's JWT. When set, it is sent in the header named by
	// Config.IdentityTokenHeader ("Authorization" by default) and the PDP
	// resolves the identity from the token itself — so ID and TypeID are not
	// required, and the mapping below disappears entirely.
	//
	// This is the natural shape for a service that already authenticates its
	// callers with a JWT: forward what arrived, and let the tenant's identity
	// template decide which claim identifies the user. It also keeps identity
	// resolution in one place — the tenant — rather than duplicated in every
	// service that calls the PDP.
	//
	// The token is a credential. It is never logged; refusals carry a short
	// fingerprint of it instead, which is enough to correlate them.
	Token string

	// ID is the user's identifier as the identity template expects it — the
	// uid the template keys on, which is not necessarily your primary key.
	// Required unless Token is set.
	ID string

	// TypeID is the identity template id. Defaults to Config.EntityTypeID.
	// Required unless Token is set. A wrong value denies everything, with
	// RT-087 if you are lucky and silently if you are not.
	TypeID string

	// Attributes are identity attributes supplied inline, as name → values.
	// Values are always arrays: {"region": {"US"}}, never a bare string. A
	// scalar does not error, it fails to match, and you get a silent deny.
	//
	// They can accompany a Token: the tenant resolves the identity from the
	// JWT, and these add attributes the token does not carry.
	Attributes map[string][]string
}

// IdentityFromToken describes a caller by their JWT alone, leaving the PDP to
// resolve who they are:
//
//	id := plainid.IdentityFromToken(plainid.TokenFromAuthorization(
//		r.Header.Get("Authorization")))
//	ok := client.Can(ctx, id, "Read", account)
func IdentityFromToken(token string) Identity {
	return Identity{Token: token}
}

// TokenFromAuthorization strips the scheme from an Authorization header value,
// returning the bare token. It accepts a value with no scheme unchanged, so it
// is safe to run over whatever arrived.
func TokenFromAuthorization(value string) string {
	value = strings.TrimSpace(value)
	if i := strings.IndexByte(value, ' '); i > 0 {
		switch strings.ToLower(value[:i]) {
		case "bearer", "jwt":
			return strings.TrimSpace(value[i+1:])
		}
	}
	return value
}

// Resource is the thing being protected: a domain object your application
// names, not a URL. The other half of the mapping.
type Resource struct {
	// Type is the PlainID resource type (asset template) name. Required.
	Type string
	// Action is what is being attempted — "Read", "Approve", "Export".
	// Can sets this from its own argument.
	Action string
	// Path identifies the specific asset, where policies address assets
	// individually. Empty asks about the resource type as a whole.
	Path string
	// Attributes are the asset's attributes, as name → values. Arrays,
	// always, for the same reason as Identity.Attributes.
	Attributes map[string][]string
	// Prefetch asks the PDP to resolve this resource type's data up front.
	Prefetch bool
}

// Query is a full permit-deny question. Use it directly when you need several
// resources in one call, context or environment data, or per-call overrides;
// Ask builds the common single-resource case.
type Query struct {
	Identity Identity

	// Resources are the resources being asked about. Several may be asked in
	// one call, and doing so is much better than looping Can — but if you are
	// checking *many*, you are asking the wrong API: that is what Policy
	// Resolution is for.
	Resources []Resource

	// ContextData and Environment are values policies match on beyond
	// identity and asset — dynamic groups, environmental conditions.
	ContextData map[string][]string
	Environment map[string][]string

	// RemoteIP is the caller's resolved address. Behind a proxy, pass the
	// client's address rather than your own; it only matters if policies use
	// it.
	RemoteIP string
	// TimeZoneOffset lets time-of-day conditions evaluate in the user's
	// terms.
	TimeZoneOffset float64

	// IncludeDetails, IncludeDenyReason and UseCache override the configured
	// defaults for one call. Nil means "use the configuration".
	IncludeDetails    *bool
	IncludeDenyReason *bool
	UseCache          *bool

	// BearerToken authenticates this one call instead of the configured
	// credentials — how a service forwards the caller's own token.
	BearerToken string

	// RequestID correlates this decision with the PDP's audit record. One is
	// generated when empty.
	RequestID string
}

// Ask builds the common question: may this identity perform this action on
// this resource?
func Ask(id Identity, action string, res Resource) Query {
	res.Action = action
	return Query{Identity: id, Resources: []Resource{res}}
}

// Can answers "may this identity perform action on resource?" with one v3
// permit-deny call.
//
// It is total and fails closed: an unreachable PDP, a timeout, a non-200, an
// unparseable body, a missing result and any result other than PERMIT all
// return false. Use Check when you need to know *why*.
func (c *Client) Can(ctx context.Context, id Identity, action string, res Resource) bool {
	return c.Check(ctx, Ask(id, action, res)).Permit
}

// Check makes one v3 permit-deny call and returns the whole outcome: the
// verdict, the reason it was refused, the per-resource breakdown when details
// were requested, and the error when the PDP did not answer.
//
// With several resources, the verdict is the PDP's verdict for the request as
// a whole. Ask for details when you need to know which resource failed.
func (c *Client) Check(ctx context.Context, q Query) Decision {
	requestID := q.RequestID
	if requestID == "" {
		requestID = NewRequestID()
	}
	d := Decision{RequestID: requestID}

	payload, err := c.buildPermitDeny(q)
	if err != nil {
		// A malformed question is a refusal like any other: we did not get a
		// permit, so there is no permit to return.
		d.Reason, d.Err = "invalid authorization query", err
		c.logDecision(q, d)
		return d
	}
	auth, err := c.resolveAuth(q.Identity.Token, q.BearerToken)
	if err != nil {
		d.Reason, d.Err = "credentials cannot be sent as configured", err
		c.logDecision(q, d)
		return d
	}

	raw, perr := c.post(ctx, c.endpoints.permitDeny, payload, requestID, c.apply(auth))
	if perr != nil {
		d.Reason, d.Err = perr.Reason, perr
		c.logDecision(q, d)
		return d
	}

	var parsed permitDenyResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		d.Reason = "PDP response unparseable"
		d.Err = &pdpError{Reason: d.Reason, Err: err}
		c.logDecision(q, d)
		return d
	}

	answer := parsed.body()
	d.Result = answer.Result
	if len(answer.Response) > 0 {
		r := answer.Response[0]
		d.Allowed, d.Denied, d.NotApplicable = r.Allowed, r.Denied, r.NotApplicable
	}
	d.DenyReason = answer.denyReason()

	switch {
	case d.Result == permitResult:
		d.Permit = true
	case d.Result == "":
		d.Reason = "PDP response has no data.result"
	case d.NoPolicyMatched():
		// Worth its own reason: no policy addressed the resource at all,
		// which is a policy modeling gap rather than a decision.
		d.Reason = "no policy addressed the resource"
	default:
		d.Reason = "policy denied"
	}
	c.logDecision(q, d)
	return d
}

// logDecision records every v3 decision. Authorization is the thing people ask
// questions about after the fact, and the request id is what ties this record
// to the PDP's own.
func (c *Client) logDecision(q Query, d Decision) {
	if d.Permit {
		if c.cfg.EnableTracing {
			c.cfg.Logger.Info("plainid: permit",
				"requestId", d.RequestID, "identity", c.describeIdentity(q.Identity),
				"resources", describeResources(q.Resources))
		}
		return
	}
	args := []any{
		"requestId", d.RequestID,
		"identity", c.describeIdentity(q.Identity),
		"resources", describeResources(q.Resources),
		"reason", d.Reason,
		"result", d.Result,
		"failure", d.Failed(),
	}
	if t := c.entityTypeID(q.Identity); t != "" {
		// A wrong identity template is the most common cause of a blanket
		// deny, so it is worth having in the line — when there is one at all.
		args = append(args, "entityTypeId", t)
	}
	if d.DenyReason != "" {
		args = append(args, "denyReason", d.DenyReason)
	}
	if d.Err != nil {
		args = append(args, "error", d.Err)
	}
	c.cfg.Logger.Warn("plainid: denied", args...)
}

// describeIdentity names the caller for a log line. With a JWT there is no
// entityId to log and the token itself must never be written down, so a short
// fingerprint stands in: it is stable per token, which is enough to correlate
// repeated denials for one user.
func (c *Client) describeIdentity(id Identity) string {
	if id.ID != "" {
		return id.ID
	}
	return identityFingerprint(id.Token)
}

// describeResources renders the resources asked about for a log line, without
// their attributes — those can carry business data.
func describeResources(resources []Resource) string {
	parts := make([]string, 0, len(resources))
	for _, r := range resources {
		if r.Path != "" {
			parts = append(parts, fmt.Sprintf("%s:%s(%s)", r.Type, r.Action, r.Path))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s", r.Type, r.Action))
	}
	return strings.Join(parts, ",")
}

// The v3 wire format. These types exist only here: nothing above this line in
// the call stack should ever see entityTypeId or assetAttributes.

type permitDenyPayload struct {
	EntityID          string              `json:"entityId,omitempty"`
	EntityTypeID      string              `json:"entityTypeId,omitempty"`
	EntityAttributes  map[string][]string `json:"entityAttributes,omitempty"`
	ListOfResources   []resourceGroup     `json:"listOfResources"`
	ContextData       map[string][]string `json:"contextData,omitempty"`
	Environment       map[string][]string `json:"environment,omitempty"`
	RemoteIP          string              `json:"remoteIp,omitempty"`
	TimeZoneOffset    float64             `json:"timeZoneOffset"`
	IncludeDetails    bool                `json:"includeDetails"`
	IncludeDenyReason bool                `json:"includeDenyReason"`
	UseCache          bool                `json:"useCache"`
}

type resourceGroup struct {
	ResourceType string          `json:"resourceType"`
	Prefetch     bool            `json:"prefetch,omitempty"`
	Resources    []resourceEntry `json:"resources"`
}

type resourceEntry struct {
	Action          string              `json:"action"`
	Path            string              `json:"path,omitempty"`
	AssetAttributes map[string][]string `json:"assetAttributes,omitempty"`
}

// permitDenyResponse accepts both shapes the runtime API answers with.
//
// The documentation shows a data envelope — {"data":{"result":"PERMIT"}} — and
// some deployments answer exactly that. Others answer at the top level:
// {"result":"PERMIT","response":[…]}. A client that reads only one of them
// finds nothing in the other and denies every request, with no error anywhere
// to explain it, so this reads whichever arrived.
type permitDenyResponse struct {
	data permitDenyData
}

// UnmarshalJSON reads the envelope when there is one and the top level
// otherwise. It is written as a method, with the payload unexported and
// reachable only through body(), so that no caller can accidentally read the
// half of the answer that happened to be empty — a mistake that compiles
// cleanly and denies every request.
func (r *permitDenyResponse) UnmarshalJSON(b []byte) error {
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &envelope); err != nil {
		return err
	}
	if len(envelope.Data) > 0 && string(envelope.Data) != "null" {
		return json.Unmarshal(envelope.Data, &r.data)
	}
	return json.Unmarshal(b, &r.data)
}

// body returns whichever shape the PDP used.
func (r permitDenyResponse) body() permitDenyData { return r.data }

type permitDenyData struct {
	Result   string              `json:"result"`
	Response []permitDenyDetails `json:"response"`
	// Reason is the deny reason, returned when includeDenyReason is set.
	// Observed as an array of policy codes (["PID005"]); documented as a
	// singular field. Both are read, and neither is modelled beyond text —
	// the shape is not fixed across tenants and versions.
	Reason     json.RawMessage `json:"reason"`
	DenyReason json.RawMessage `json:"denyReason"`
}

type permitDenyDetails struct {
	Allowed       []ResourceRef `json:"allowed"`
	Denied        []ResourceRef `json:"denied"`
	NotApplicable []ResourceRef `json:"not_applicable"`
}

func (d permitDenyData) denyReason() string {
	for _, raw := range []json.RawMessage{d.Reason, d.DenyReason} {
		if text := renderJSONText(raw); text != "" {
			return text
		}
	}
	return ""
}

// renderJSONText turns a string, an array of strings, or anything else into
// one line of log-safe text.
func renderJSONText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return strings.Join(list, ", ")
	}
	return string(raw)
}

// buildPermitDeny maps a Query onto the wire payload. This and the token
// builder are the only places that know PlainID's field names.
func (c *Client) buildPermitDeny(q Query) (permitDenyPayload, error) {
	p := permitDenyPayload{
		EntityID:          strings.TrimSpace(q.Identity.ID),
		EntityTypeID:      c.entityTypeID(q.Identity),
		EntityAttributes:  attributes(q.Identity.Attributes),
		ContextData:       attributes(q.ContextData),
		Environment:       attributes(q.Environment),
		RemoteIP:          q.RemoteIP,
		TimeZoneOffset:    q.TimeZoneOffset,
		IncludeDetails:    boolOr(q.IncludeDetails, c.cfg.IncludeDetails),
		IncludeDenyReason: boolOr(q.IncludeDenyReason, c.cfg.IncludeDenyReason),
		UseCache:          boolOr(q.UseCache, c.cfg.useCache()),
	}
	// With a JWT, the PDP resolves the identity from the token, so neither of
	// these is required — and both are omitted from the payload when empty.
	if q.Identity.Token == "" {
		if p.EntityID == "" {
			return p, errors.New("plainid: Identity.ID is required (or set Identity.Token to let the PDP resolve the identity from a JWT)")
		}
		if p.EntityTypeID == "" {
			return p, errors.New("plainid: Identity.TypeID is required (or set Config.EntityTypeID, or set Identity.Token)")
		}
	}
	if len(q.Resources) == 0 {
		return p, errors.New("plainid: at least one Resource is required")
	}

	// Group by resource type, keeping the order resources were asked in, so
	// a recorded payload is stable and diffable in a test.
	index := map[string]int{}
	for _, r := range q.Resources {
		if strings.TrimSpace(r.Type) == "" {
			return p, errors.New("plainid: Resource.Type is required")
		}
		if strings.TrimSpace(r.Action) == "" {
			return p, fmt.Errorf("plainid: Resource.Action is required (resource type %q)", r.Type)
		}
		i, ok := index[r.Type]
		if !ok {
			i = len(p.ListOfResources)
			index[r.Type] = i
			p.ListOfResources = append(p.ListOfResources, resourceGroup{ResourceType: r.Type})
		}
		g := &p.ListOfResources[i]
		g.Prefetch = g.Prefetch || r.Prefetch
		g.Resources = append(g.Resources, resourceEntry{
			Action:          r.Action,
			Path:            r.Path,
			AssetAttributes: attributes(r.Attributes),
		})
	}
	return p, nil
}

// entityTypeID resolves the identity template id, per call or from
// configuration.
func (c *Client) entityTypeID(id Identity) string {
	if t := strings.TrimSpace(id.TypeID); t != "" {
		return t
	}
	// A configured default must not be smuggled into a token-based call: the
	// point of sending the JWT is that the tenant decides which identity
	// template applies.
	if id.Token != "" {
		return ""
	}
	return c.cfg.EntityTypeID
}

// attributes copies an attribute map, dropping empty entries. It returns nil
// for an empty map so the field is omitted rather than sent as {}.
//
// The array-of-values shape is enforced by the type: a bare string will not
// compile, which is the cheapest possible fix for the most common silent-deny
// bug in PlainID clients.
func attributes(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		if k == "" || len(v) == 0 {
			continue
		}
		out[k] = append([]string(nil), v...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func boolOr(override *bool, fallback bool) bool {
	if override != nil {
		return *override
	}
	return fallback
}

// Bool returns a pointer to v, for the per-call override fields.
func Bool(v bool) *bool { return &v }
