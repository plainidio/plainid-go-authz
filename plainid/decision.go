package plainid

import "strings"

// Decision is the outcome of one authorization call, whichever permit-deny
// endpoint produced it.
//
// It is total: every path through the client returns one, and Permit is true
// only when the PDP explicitly said PERMIT. There is no "unknown" for a
// caller to interpret, because callers interpret unknown as allow.
type Decision struct {
	// Permit is true only when the PDP answered with the exact string PERMIT.
	Permit bool
	// Result is the raw result string, empty if none was returned.
	Result string
	// RequestID correlates this decision with the PDP's audit record. It is
	// usually the only way to answer "why was this denied" afterwards.
	RequestID string
	// Reason describes why a request was refused, for logs only. It is never
	// shown to the caller.
	Reason string
	// Err is set when the refusal came from a failure rather than a policy.
	// It wraps ErrPDPUnavailable.
	Err error

	// Allowed, Denied and NotApplicable are the per-resource breakdown the
	// v3 endpoint returns when details are requested. They are empty
	// otherwise, and always empty for the 5.0 endpoint.
	Allowed       []ResourceRef
	Denied        []ResourceRef
	NotApplicable []ResourceRef

	// DenyReason is the PDP's own explanation, present only when deny
	// reasons were requested. Treat it as internal: surfacing it to end
	// users leaks policy structure.
	DenyReason string
}

// ResourceRef identifies one resource in a detailed v3 answer.
type ResourceRef struct {
	Path     string `json:"path"`
	Action   string `json:"action"`
	Template string `json:"template"`
	// Reason is the policy code explaining a denial, present on entries in
	// Denied when deny reasons were requested. Internal: it describes your
	// policy structure, so log it rather than returning it.
	Reason string `json:"reason,omitempty"`
}

// Failed reports whether this refusal came from the PDP not answering rather
// than from policy. Log the two differently: an outage that is
// indistinguishable from a denial in your own logs cannot be operated, and
// the first incident becomes the argument for failing open.
func (d Decision) Failed() bool { return d.Err != nil }

// DeniedByPolicy reports a real verdict of deny — the PDP answered, and said
// no.
func (d Decision) DeniedByPolicy() bool { return !d.Permit && d.Err == nil }

// NoPolicyMatched reports that the PDP addressed no policy to the resources
// asked about. That is a policy *modeling* gap; it reads identically to a
// denial from the caller's side, which is correct, but debugging it as a code
// bug wastes a day. Only meaningful when details were requested.
func (d Decision) NoPolicyMatched() bool {
	return !d.Permit && len(d.Allowed) == 0 && len(d.NotApplicable) > 0
}

// Allows reports whether a specific resource came back allowed. Only
// meaningful when details were requested; without them a batch answer is one
// verdict for the whole request. An empty action or path matches any.
func (d Decision) Allows(resourceType, action, path string) bool {
	for _, r := range d.Allowed {
		if !equalFoldOrEmpty(r.Template, resourceType) {
			continue
		}
		if action != "" && !equalFoldOrEmpty(r.Action, action) {
			continue
		}
		if path != "" && r.Path != path {
			continue
		}
		return true
	}
	return false
}

// equalFoldOrEmpty compares two names case-insensitively. Resource types and
// actions are configured strings, and tenants are not consistent about case —
// "View" and "view" both appear in PlainID's own examples.
func equalFoldOrEmpty(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
