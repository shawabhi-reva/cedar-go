package cedar

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go/internal/testutil"
	"github.com/cedar-policy/cedar-go/types"
)

// policySetByID builds a PolicySet keyed by each policy's @id annotation, so
// diagnostic reasons can be compared by name.
func policySetByID(t *testing.T, doc string) *PolicySet {
	t.Helper()
	list, err := NewPolicyListFromBytes("policy.cedar", []byte(doc))
	testutil.OK(t, err)
	ps := NewPolicySet()
	for _, p := range list {
		ps.Store(PolicyID(p.Annotations()["id"]), p)
	}
	return ps
}

func conditionalRequest() Request {
	return Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "delete"),
		Resource:  types.NewEntityUID("Doc", "prod"),
		Context:   types.Record{},
	}
}

func reasonIDs(diag Diagnostic) []PolicyID {
	var ids []PolicyID
	for _, r := range diag.Reasons {
		ids = append(ids, r.PolicyID)
	}
	slices.Sort(ids)
	return ids
}

// Every combination of satisfied permit / conditional / forbid policies:
// forbid > conditional > permit > default deny.
func TestConditionalPrecedence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		permit, conditional, forbid bool
		want                        Decision
		reasons                     []PolicyID
	}{
		{false, false, false, Deny, nil},
		{true, false, false, Allow, []PolicyID{"p"}},
		{false, true, false, ConditionalAllow, []PolicyID{"c"}},
		{true, true, false, ConditionalAllow, []PolicyID{"c"}},
		{false, false, true, Deny, []PolicyID{"f"}},
		{true, false, true, Deny, []PolicyID{"f"}},
		{false, true, true, Deny, []PolicyID{"f"}},
		{true, true, true, Deny, []PolicyID{"f"}},
	}
	for _, tt := range tests {
		tt := tt
		var doc strings.Builder
		var name []string
		if tt.permit {
			doc.WriteString(`@id("p") permit (principal, action, resource);`)
			name = append(name, "permit")
		}
		if tt.conditional {
			doc.WriteString(`@id("c") conditional (principal, action, resource);`)
			name = append(name, "conditional")
		}
		if tt.forbid {
			doc.WriteString(`@id("f") forbid (principal, action, resource);`)
			name = append(name, "forbid")
		}
		t.Run(strings.Join(append(name, "case"), "/"), func(t *testing.T) {
			t.Parallel()
			ps := policySetByID(t, doc.String())
			got, diag := ps.IsAuthorized(types.Entities{}, conditionalRequest())
			testutil.Equals(t, got, tt.want)
			testutil.Equals(t, reasonIDs(diag), tt.reasons)
		})
	}
}

// Obligations travel as annotations on the conditional policies reported as the reason.
func TestConditionalReasonCarriesAnnotations(t *testing.T) {
	t.Parallel()
	ps := policySetByID(t, `
		@id("admins") permit (principal, action, resource);
		@id("needs-mfa") @obligation("mfa") conditional (principal, action, resource);
	`)
	got, diag := ps.IsAuthorized(types.Entities{}, conditionalRequest())
	testutil.Equals(t, got, ConditionalAllow)
	testutil.Equals(t, reasonIDs(diag), []PolicyID{"needs-mfa"})
	testutil.Equals(t, ps.Get("needs-mfa").Annotations()["obligation"], types.String("mfa"))
}

// An erroring conditional is skipped, exactly like an erroring forbid.
func TestConditionalSkipOnError(t *testing.T) {
	t.Parallel()
	ps := policySetByID(t, `
		@id("p") permit (principal, action, resource);
		@id("c") conditional (principal, action, resource) when { context.missing == 1 };
	`)
	got, diag := ps.IsAuthorized(types.Entities{}, conditionalRequest())
	testutil.Equals(t, got, Allow)
	testutil.Equals(t, len(diag.Errors), 1)
	testutil.Equals(t, diag.Errors[0].PolicyID, PolicyID("c"))
}

func TestConditionalCedarAndJSONRoundTrip(t *testing.T) {
	t.Parallel()
	var p Policy
	testutil.OK(t, p.UnmarshalCedar([]byte(`@obligation("mfa")
conditional (principal, action, resource)
when { context.mfa };`)))
	testutil.Equals(t, p.Effect(), Conditional)

	text := string(p.MarshalCedar())
	testutil.Equals(t, strings.Contains(text, "conditional ("), true)
	var fromText Policy
	testutil.OK(t, fromText.UnmarshalCedar([]byte(text)))
	testutil.Equals(t, fromText.Effect(), Conditional)

	js, err := p.MarshalJSON()
	testutil.OK(t, err)
	var shape struct {
		Effect string `json:"effect"`
	}
	testutil.OK(t, json.Unmarshal(js, &shape))
	testutil.Equals(t, shape.Effect, "conditional")
	var fromJSON Policy
	testutil.OK(t, fromJSON.UnmarshalJSON(js))
	testutil.Equals(t, fromJSON.Effect(), Conditional)
}

// Adding the effect must not stop `conditional` from being used as a name.
func TestConditionalIsStillAValidAttributeName(t *testing.T) {
	t.Parallel()
	ps, err := NewPolicySetFromBytes("policy.cedar", []byte(`
		permit (principal, action, resource) when { context has conditional && context.conditional };
	`))
	testutil.OK(t, err)
	req := conditionalRequest()
	req.Context = types.Record{"conditional": types.True}
	got, _ := ps.IsAuthorized(types.Entities{}, req)
	testutil.Equals(t, got, Allow)
}

// The location example: the same principal, two locations.
func TestConditionalLocationExample(t *testing.T) {
	t.Parallel()
	ps := policySetByID(t, `
		@id("allow-bangalore")
		permit (principal == Demo::User::"abhishek", action, resource)
		when { principal.location == "bangalore" };

		@id("deny-delhi")
		forbid (principal == Demo::User::"abhishek", action, resource)
		when { principal.location == "delhi" };

		@id("abhishek-conditional")
		@obligation("manager-approval")
		conditional (principal == Demo::User::"abhishek", action, resource);
	`)
	abhishek := types.NewEntityUID("Demo::User", "abhishek")
	req := Request{
		Principal: abhishek,
		Action:    types.NewEntityUID("Demo::Action", "access"),
		Resource:  types.NewEntityUID("Demo::App", "portal"),
		Context:   types.Record{},
	}
	for _, tt := range []struct {
		location string
		want     Decision
		reasons  []PolicyID
	}{
		{"delhi", Deny, []PolicyID{"deny-delhi"}},
		{"bangalore", ConditionalAllow, []PolicyID{"abhishek-conditional"}},
	} {
		entities := types.Entities{abhishek: &types.Entity{
			UID:        abhishek,
			Attributes: types.Record{"location": types.String(tt.location)},
		}}
		got, diag := ps.IsAuthorized(entities, req)
		testutil.Equals(t, got, tt.want)
		testutil.Equals(t, reasonIDs(diag), tt.reasons)
	}
}
