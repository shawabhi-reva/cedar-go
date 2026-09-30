package cedar

import (
	"iter"

	"github.com/cedar-policy/cedar-go/internal/eval"
	"github.com/cedar-policy/cedar-go/types"
)

// PolicyIterator is an interface which abstracts an iterable set of policies.
type PolicyIterator interface {
	// All returns an iterator over all the policies in the set
	All() iter.Seq2[PolicyID, *Policy]
}

// Authorize uses the combination of the PolicySet and Entities to determine
// if the given Request to determine Decision and Diagnostic.
func Authorize(policies PolicyIterator, entities types.EntityGetter, req Request) (Decision, Diagnostic) {
	if entities == nil {
		var zero types.EntityMap
		entities = zero
	}
	env := eval.Env{
		Entities:  entities,
		Principal: req.Principal,
		Action:    req.Action,
		Resource:  req.Resource,
		Context:   req.Context,
	}
	var diag Diagnostic
	var forbids []DiagnosticReason
	var conditionals []DiagnosticReason
	var permits []DiagnosticReason
	// Don't try to short circuit this.
	// - Even though single forbid means forbid
	// - All policy should be run to collect errors
	// - For permit, all permits must be run to collect annotations
	// - For forbid, forbids must be run to collect annotations
	// - For conditional, conditionals must be run to collect annotations (obligations)
	for id, po := range policies.All() {
		result, err := po.eval.Eval(env)
		if err != nil {
			diag.Errors = append(diag.Errors, DiagnosticError{PolicyID: id, Position: po.Position(), Message: err.Error()})
			continue
		}
		if !result {
			continue
		}
		reason := DiagnosticReason{PolicyID: id, Position: po.Position()}
		switch po.Effect() {
		case Forbid:
			forbids = append(forbids, reason)
		case Conditional:
			conditionals = append(conditionals, reason)
		default:
			permits = append(permits, reason)
		}
	}
	// Precedence: forbid > conditional > permit > default deny.
	if len(forbids) > 0 {
		diag.Reasons = forbids
		return Deny, diag
	}
	if len(conditionals) > 0 {
		diag.Reasons = conditionals
		return ConditionalAllow, diag
	}
	if len(permits) > 0 {
		diag.Reasons = permits
		return Allow, diag
	}
	return Deny, diag
}
