package cedar_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/internal/testutil"
)

// policySetByID builds a PolicySet keyed by each policy's @id annotation, so
// diagnostic reasons can be compared by name.
func policySetByID(t *testing.T, doc string) *cedar.PolicySet {
	t.Helper()
	list, err := cedar.NewPolicyListFromBytes("policy.cedar", []byte(doc))
	testutil.OK(t, err)
	ps := cedar.NewPolicySet()
	for _, p := range list {
		testutil.Equals(t, ps.Add(cedar.PolicyID(p.Annotations()["id"]), p), true)
	}
	return ps
}

func conditionalRequest() cedar.Request {
	return cedar.Request{
		Principal: cedar.NewEntityUID("User", "alice"),
		Action:    cedar.NewEntityUID("Action", "delete"),
		Resource:  cedar.NewEntityUID("Doc", "prod"),
		Context:   cedar.Record{},
	}
}

func reasonIDs(diag cedar.Diagnostic) []cedar.PolicyID {
	var ids []cedar.PolicyID
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
		want                        cedar.Decision
		reasons                     []cedar.PolicyID
	}{
		{false, false, false, cedar.Deny, nil},
		{true, false, false, cedar.Allow, []cedar.PolicyID{"p"}},
		{false, true, false, cedar.ConditionalAllow, []cedar.PolicyID{"c"}},
		{true, true, false, cedar.ConditionalAllow, []cedar.PolicyID{"c"}},
		{false, false, true, cedar.Deny, []cedar.PolicyID{"f"}},
		{true, false, true, cedar.Deny, []cedar.PolicyID{"f"}},
		{false, true, true, cedar.Deny, []cedar.PolicyID{"f"}},
		{true, true, true, cedar.Deny, []cedar.PolicyID{"f"}},
	}
	for _, tt := range tests {
		tt := tt
		name := strings.Join([]string{
			map[bool]string{true: "permit", false: "-"}[tt.permit],
			map[bool]string{true: "conditional", false: "-"}[tt.conditional],
			map[bool]string{true: "forbid", false: "-"}[tt.forbid],
		}, "/")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var doc strings.Builder
			if tt.permit {
				doc.WriteString(`@id("p") permit (principal, action, resource);`)
			}
			if tt.conditional {
				doc.WriteString(`@id("c") conditional (principal, action, resource);`)
			}
			if tt.forbid {
				doc.WriteString(`@id("f") forbid (principal, action, resource);`)
			}
			ps := policySetByID(t, doc.String())
			got, diag := cedar.Authorize(ps, cedar.EntityMap{}, conditionalRequest())
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
	got, diag := cedar.Authorize(ps, cedar.EntityMap{}, conditionalRequest())
	testutil.Equals(t, got, cedar.ConditionalAllow)
	testutil.Equals(t, reasonIDs(diag), []cedar.PolicyID{"needs-mfa"})
	testutil.Equals(t, ps.Get("needs-mfa").Annotations()["obligation"], cedar.String("mfa"))
}

// An erroring conditional is skipped, exactly like an erroring forbid.
func TestConditionalSkipOnError(t *testing.T) {
	t.Parallel()
	ps := policySetByID(t, `
		@id("p") permit (principal, action, resource);
		@id("c") conditional (principal, action, resource) when { context.missing == 1 };
	`)
	got, diag := cedar.Authorize(ps, cedar.EntityMap{}, conditionalRequest())
	testutil.Equals(t, got, cedar.Allow)
	testutil.Equals(t, len(diag.Errors), 1)
	testutil.Equals(t, diag.Errors[0].PolicyID, cedar.PolicyID("c"))
}

func TestConditionalCedarAndJSONRoundTrip(t *testing.T) {
	t.Parallel()
	src := `@obligation("mfa")
conditional (principal, action, resource)
when { context.mfa };`
	var p cedar.Policy
	testutil.OK(t, p.UnmarshalCedar([]byte(src)))
	testutil.Equals(t, p.Effect(), cedar.Conditional)

	text := string(p.MarshalCedar())
	testutil.Equals(t, strings.Contains(text, "conditional ("), true)
	var fromText cedar.Policy
	testutil.OK(t, fromText.UnmarshalCedar([]byte(text)))
	testutil.Equals(t, fromText.Effect(), cedar.Conditional)

	js, err := p.MarshalJSON()
	testutil.OK(t, err)
	var shape struct {
		Effect string `json:"effect"`
	}
	testutil.OK(t, json.Unmarshal(js, &shape))
	testutil.Equals(t, shape.Effect, "conditional")
	var fromJSON cedar.Policy
	testutil.OK(t, fromJSON.UnmarshalJSON(js))
	testutil.Equals(t, fromJSON.Effect(), cedar.Conditional)
}

// Adding the effect must not stop `conditional` from being used as a name.
func TestConditionalIsStillAValidAttributeName(t *testing.T) {
	t.Parallel()
	ps, err := cedar.NewPolicySetFromBytes("policy.cedar", []byte(`
		permit (principal, action, resource) when { context has conditional && context.conditional };
	`))
	testutil.OK(t, err)
	req := conditionalRequest()
	req.Context = cedar.NewRecord(cedar.RecordMap{"conditional": cedar.True})
	got, _ := cedar.Authorize(ps, cedar.EntityMap{}, req)
	testutil.Equals(t, got, cedar.Allow)
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
	abhishek := cedar.NewEntityUID("Demo::User", "abhishek")
	req := cedar.Request{
		Principal: abhishek,
		Action:    cedar.NewEntityUID("Demo::Action", "access"),
		Resource:  cedar.NewEntityUID("Demo::App", "portal"),
		Context:   cedar.Record{},
	}
	for _, tt := range []struct {
		location string
		want     cedar.Decision
		reasons  []cedar.PolicyID
	}{
		{"delhi", cedar.Deny, []cedar.PolicyID{"deny-delhi"}},
		{"bangalore", cedar.ConditionalAllow, []cedar.PolicyID{"abhishek-conditional"}},
	} {
		entities := cedar.EntityMap{abhishek: cedar.Entity{
			UID:        abhishek,
			Attributes: cedar.NewRecord(cedar.RecordMap{"location": cedar.String(tt.location)}),
		}}
		got, diag := cedar.Authorize(ps, entities, req)
		testutil.Equals(t, got, tt.want)
		testutil.Equals(t, reasonIDs(diag), tt.reasons)
	}
}
