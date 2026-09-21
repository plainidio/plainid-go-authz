package plainid

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// TokenQuery asks the User Access Token API for everything an identity may
// do, in one call.
//
// This is a session-start API: render a menu, enable buttons, seed a
// client-side permission map. Ask for what the screen needs — an unbounded
// token over a large catalogue is slow to compute and large to hold.
type TokenQuery struct {
	Identity Identity

	// Assets and ResourceTypes narrow the answer. Leave both empty and the
	// PDP answers with everything the identity may do: it resolves the asset
	// list from the tenant's identity and asset sources (the PIP) and returns
	// each allowed asset with its attributes and actions, without the
	// application having to know, or send, what exists.
	//
	// That discovery call is the point of this API, and it is what an
	// application wanting "what may this user do?" should ask. Narrow only
	// when the screen genuinely needs a subset — a token over a large
	// catalogue is slow to compute and large to hold.
	//
	// One counter-intuitive detail, worth knowing before debugging it: naming
	// a resource type *without* an attribute list returns fewer asset
	// attributes than asking for everything does. If you narrow and still want
	// attributes, list them in ResourceTypeQuery.Attributes.
	Assets []Asset
	// ResourceTypes asks for whole resource types, optionally limiting which
	// attributes and actions come back.
	ResourceTypes []ResourceTypeQuery

	// Format is "JSON" (the default), "JWT" or "StandardJWT". The JWT forms
	// return a signed token instead of a permission list — see
	// Permissions.Token.
	Format string

	// UseCache overrides Config.UseCache for this call.
	UseCache *bool

	// BearerToken authenticates this one call instead of the configured
	// credentials.
	BearerToken string

	// RequestID correlates this call with the PDP's audit record.
	RequestID string
}

// Asset names one asset to ask about.
type Asset struct {
	// Template is the asset template (resource type) name.
	Template string
	// Path identifies the asset.
	Path string
	// Attributes are the asset's attributes, as name → values.
	Attributes map[string][]string
}

// ResourceTypeQuery asks for a whole resource type.
type ResourceTypeQuery struct {
	// Name is the resource type name. Required.
	Name string
	// Attributes limits which asset attributes come back. Empty means all.
	Attributes []string
	// Actions limits which actions come back. Empty means all.
	Actions []string
}

// Token access formats.
const (
	TokenFormatJSON        = "JSON"
	TokenFormatJWT         = "JWT"
	TokenFormatStandardJWT = "StandardJWT"
)

// Permissions is what an identity may do, as of the moment it was fetched.
//
// Treat it as a snapshot. Entitlements fetched at session start go stale the
// moment policy or user attributes change, so a permission map is right for
// UI affordances and session-scoped reads, and wrong for authorizing a
// consequential write — ask Can for those.
//
// The zero value permits nothing, which is what makes the fail-closed
// contract hold even for a caller that ignores the error.
type Permissions struct {
	// Validity is the PDP's tokenValidity, in seconds. Zero means the PDP
	// stated no validity period, not "valid forever".
	Validity int
	// Access is the flat list of what the identity may do.
	Access []Access
	// Token is the signed token, when Format was JWT or StandardJWT. Whatever
	// consumes it must verify the signature and honour Validity, or you have
	// shipped a permission map any client can rewrite.
	Token string
	// ContextData is the context the PDP returned alongside the entitlements,
	// kept raw because its shape is tenant-defined. Usually null.
	ContextData json.RawMessage
	// Raw is the PDP's response body, for formats this client does not model.
	Raw json.RawMessage
}

// Access is one entitlement: one asset the identity may act on, the actions
// permitted on it, and the asset's attributes as the PDP resolved them.
type Access struct {
	Path         string              `json:"path"`
	ResourceType string              `json:"resourceType"`
	Attributes   map[string][]string `json:"attributes"`
	Actions      []TokenAction       `json:"actions"`
}

// Attribute reads one asset attribute, or nil. Values are always arrays.
func (a Access) Attribute(name string) []string {
	for k, v := range a.Attributes {
		if equalFoldOrEmpty(k, name) {
			return v
		}
	}
	return nil
}

// Allows reports whether this entitlement covers an action.
func (a Access) Allows(action string) bool {
	for _, act := range a.Actions {
		if equalFoldOrEmpty(act.Action, action) {
			return true
		}
	}
	return false
}

// TokenAction is one permitted action and, where the tenant returns it, the
// permission that granted it. Permission and PermissionID are often absent.
type TokenAction struct {
	Action       string `json:"action"`
	Permission   string `json:"permission"`
	PermissionID string `json:"permissionId"`
}

// Permissions fetches everything id may do across the named resource types.
//
// Pass **no** resource types and the PDP resolves the allowed assets itself,
// from the tenant's asset sources, and returns each one with its attributes
// and actions. That is the discovery call: the application does not need to
// know what assets exist, or name them, to find out which ones this user may
// act on.
//
//	perms, err := client.Permissions(ctx, identity)   // everything, discovered
//	perms.Assets("Orders")                            // the allowed orders
//	perms.PathsFor("Orders", "Read")                  // → ["order1", "order3"]
//
// It fails closed: on any failure it returns empty Permissions, which permits
// nothing, alongside the error. Log the error; do not treat the emptiness as
// a policy answer.
func (c *Client) Permissions(ctx context.Context, id Identity, resourceTypes ...string) (Permissions, error) {
	q := TokenQuery{Identity: id}
	for _, name := range resourceTypes {
		q.ResourceTypes = append(q.ResourceTypes, ResourceTypeQuery{Name: name})
	}
	return c.AccessToken(ctx, q)
}

// AccessToken makes one User Access Token call with full control over what is
// asked for.
func (c *Client) AccessToken(ctx context.Context, q TokenQuery) (Permissions, error) {
	requestID := q.RequestID
	if requestID == "" {
		requestID = NewRequestID()
	}

	payload, err := c.buildToken(q)
	if err != nil {
		c.logTokenFailure(q, requestID, "invalid token query", err)
		return Permissions{}, err
	}
	auth, err := c.resolveAuth(q.Identity.Token, q.BearerToken)
	if err != nil {
		c.logTokenFailure(q, requestID, "credentials cannot be sent as configured", err)
		return Permissions{}, err
	}

	raw, perr := c.post(ctx, c.endpoints.token, payload, requestID, c.apply(auth))
	if perr != nil {
		c.logTokenFailure(q, requestID, perr.Reason, perr)
		return Permissions{}, perr
	}

	// Note the shape difference from permit-deny: no data envelope. Reading
	// data.result here would find nothing and look like a denial.
	var parsed tokenResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		wrapped := &pdpError{Reason: "PDP response unparseable", Err: err}
		c.logTokenFailure(q, requestID, wrapped.Reason, wrapped)
		return Permissions{}, wrapped
	}

	p := Permissions{Validity: parsed.TokenValidity, ContextData: parsed.ContextData, Raw: raw}
	for _, r := range parsed.Response {
		p.Access = append(p.Access, r.Access...)
		if r.AccessToken != "" {
			p.Token = r.AccessToken
		}
	}
	if c.cfg.EnableTracing {
		c.cfg.Logger.Info("plainid: access token",
			"requestId", requestID, "identity", c.describeIdentity(q.Identity),
			"resourceTypes", len(p.ResourceTypes()), "entitlements", len(p.Access))
	}
	return p, nil
}

func (c *Client) logTokenFailure(q TokenQuery, requestID, reason string, err error) {
	args := []any{
		"requestId", requestID,
		"identity", c.describeIdentity(q.Identity),
		"reason", reason,
		"error", err,
		// Said plainly, because the caller now holds an empty permission map
		// and the difference between "may do nothing" and "we could not ask"
		// is the whole story.
		"result", "no permissions returned",
	}
	if t := c.entityTypeID(q.Identity); t != "" {
		args = append(args, "entityTypeId", t)
	}
	c.cfg.Logger.Warn("plainid: access token failed", args...)
}

// IsEmpty reports that this token permits nothing.
func (p Permissions) IsEmpty() bool { return len(p.Access) == 0 }

// Allows reports whether the identity may perform action on any asset of
// resourceType. Comparison is case-insensitive: tenants are not consistent
// about case, and "View" and "view" both appear in PlainID's own examples.
func (p Permissions) Allows(resourceType, action string) bool {
	return p.AllowsPath(resourceType, "", action)
}

// AllowsPath reports whether the identity may perform action on one specific
// asset. An empty path matches any asset of the resource type.
func (p Permissions) AllowsPath(resourceType, path, action string) bool {
	for _, a := range p.Access {
		if !equalFoldOrEmpty(a.ResourceType, resourceType) {
			continue
		}
		if path != "" && a.Path != path {
			continue
		}
		for _, act := range a.Actions {
			if equalFoldOrEmpty(act.Action, action) {
				return true
			}
		}
	}
	return false
}

// Actions lists the distinct actions permitted on a resource type, sorted.
func (p Permissions) Actions(resourceType string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range p.Access {
		if !equalFoldOrEmpty(a.ResourceType, resourceType) {
			continue
		}
		for _, act := range a.Actions {
			if act.Action != "" && !seen[act.Action] {
				seen[act.Action] = true
				out = append(out, act.Action)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ResourceTypes lists the distinct resource types this token carries, sorted.
func (p Permissions) ResourceTypes() []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range p.Access {
		if a.ResourceType != "" && !seen[a.ResourceType] {
			seen[a.ResourceType] = true
			out = append(out, a.ResourceType)
		}
	}
	sort.Strings(out)
	return out
}

// Paths lists the distinct asset paths permitted under a resource type,
// sorted.
func (p Permissions) Paths(resourceType string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range p.Access {
		if !equalFoldOrEmpty(a.ResourceType, resourceType) || a.Path == "" {
			continue
		}
		if !seen[a.Path] {
			seen[a.Path] = true
			out = append(out, a.Path)
		}
	}
	sort.Strings(out)
	return out
}

// Assets lists the entitlements for a resource type, each carrying the asset's
// path, its attributes and the actions permitted on it. An empty resourceType
// returns all of them.
//
// This is what a discovery call is for: the PDP resolved which assets exist
// and which of them this identity may touch, so the application can render
// them without knowing the catalogue.
func (p Permissions) Assets(resourceType string) []Access {
	out := make([]Access, 0, len(p.Access))
	for _, a := range p.Access {
		if resourceType == "" || equalFoldOrEmpty(a.ResourceType, resourceType) {
			out = append(out, a)
		}
	}
	return out
}

// PathsFor lists the asset paths on which one action is permitted, sorted.
//
// For a bounded catalogue this is directly usable as a filter — the ids to
// fetch, or an IN clause. It does not scale to an unbounded one: the token
// enumerates every allowed asset, so a table of a million rows produces a
// token of a million entries. That is the Policy Resolution API's job, which
// returns the constraint instead of the list.
func (p Permissions) PathsFor(resourceType, action string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range p.Access {
		if !equalFoldOrEmpty(a.ResourceType, resourceType) || a.Path == "" {
			continue
		}
		if a.Allows(action) && !seen[a.Path] {
			seen[a.Path] = true
			out = append(out, a.Path)
		}
	}
	sort.Strings(out)
	return out
}

// Map renders the token as resource type → actions, which is the shape a UI
// or a front end usually wants. Serialize this rather than the whole token
// when seeding a client: it carries no asset attributes and no permission
// names, so it leaks less of your policy structure.
func (p Permissions) Map() map[string][]string {
	out := map[string][]string{}
	for _, t := range p.ResourceTypes() {
		out[t] = p.Actions(t)
	}
	return out
}

// The token wire format.

type tokenPayload struct {
	EntityID          string              `json:"entityId,omitempty"`
	EntityTypeID      string              `json:"entityTypeId,omitempty"`
	EntityAttributes  map[string][]string `json:"entityAttributes,omitempty"`
	AssetList         []tokenAsset        `json:"assetList,omitempty"`
	ResourceTypes     []tokenResourceType `json:"resourceTypes,omitempty"`
	AccessTokenFormat string              `json:"accessTokenFormat"`
	UseCache          bool                `json:"useCache"`
}

type tokenAsset struct {
	Template        string              `json:"template"`
	Path            string              `json:"path,omitempty"`
	AssetAttributes map[string][]string `json:"assetAttributes,omitempty"`
}

type tokenResourceType struct {
	Name          string   `json:"name"`
	AttributeList []string `json:"attributeList,omitempty"`
	Actions       []string `json:"actions,omitempty"`
}

type tokenResponse struct {
	TokenValidity int             `json:"tokenValidity"`
	ContextData   json.RawMessage `json:"contextData"`
	Response      []struct {
		Access []Access `json:"access"`
		// Present for the JWT formats. Unverified against a live tenant;
		// Permissions.Raw carries the whole body either way.
		AccessToken string `json:"accessToken"`
	} `json:"response"`
}

func (c *Client) buildToken(q TokenQuery) (tokenPayload, error) {
	p := tokenPayload{
		EntityID:          strings.TrimSpace(q.Identity.ID),
		EntityTypeID:      c.entityTypeID(q.Identity),
		EntityAttributes:  attributes(q.Identity.Attributes),
		AccessTokenFormat: tokenFormat(q.Format),
		UseCache:          boolOr(q.UseCache, c.cfg.useCache()),
	}
	// As with permit-deny: a JWT lets the PDP resolve the identity itself.
	if q.Identity.Token == "" {
		if p.EntityID == "" {
			return p, errors.New("plainid: Identity.ID is required (or set Identity.Token to let the PDP resolve the identity from a JWT)")
		}
		if p.EntityTypeID == "" {
			return p, errors.New("plainid: Identity.TypeID is required (or set Config.EntityTypeID, or set Identity.Token)")
		}
	}
	for _, a := range q.Assets {
		if strings.TrimSpace(a.Template) == "" {
			return p, errors.New("plainid: Asset.Template is required")
		}
		p.AssetList = append(p.AssetList, tokenAsset{
			Template:        a.Template,
			Path:            a.Path,
			AssetAttributes: attributes(a.Attributes),
		})
	}
	for _, rt := range q.ResourceTypes {
		if strings.TrimSpace(rt.Name) == "" {
			return p, errors.New("plainid: ResourceTypeQuery.Name is required")
		}
		p.ResourceTypes = append(p.ResourceTypes, tokenResourceType{
			Name:          rt.Name,
			AttributeList: rt.Attributes,
			Actions:       rt.Actions,
		})
	}
	return p, nil
}

func tokenFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		return TokenFormatJSON
	case "jwt":
		return TokenFormatJWT
	case "standardjwt":
		return TokenFormatStandardJWT
	default:
		// Pass an unrecognized value through: a tenant may support a format
		// this client has not heard of, and the PDP will reject it clearly.
		return format
	}
}
