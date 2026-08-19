package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/ghostguard/ghostguard/internal/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

type Engine struct {
	modules  map[string]*ast.Module
	prepared rego.PreparedEvalQuery
}

func NewEngine() *Engine {
	return &Engine{
		modules: make(map[string]*ast.Module),
	}
}

func (e *Engine) LoadPolicy(name, module string) error {
	parsed, err := ast.ParseModuleWithOpts(name, module, ast.ParserOptions{})
	if err != nil {
		return fmt.Errorf("parsing policy %s: %w", name, err)
	}
	e.modules[name] = parsed

	// Build a single query from all modules.
	// All policies share package ghostguard, so we query data.ghostguard
	// and inspect the full result map for deny/allow/log rules.
	var opts []func(*rego.Rego)
	opts = append(opts, rego.Query("data.ghostguard"))
	for n, m := range e.modules {
		opts = append(opts, rego.Module(n, m.String()))
	}
	r := rego.New(opts...)
	prepared, err := r.PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("preparing combined policy: %w", err)
	}
	e.prepared = prepared
	return nil
}

func isTrueSet(val interface{}) bool {
	s, ok := val.(ast.Set)
	if ok && s.Len() > 0 {
		return true
	}
	return false
}

func (e *Engine) Evaluate(toolCall *model.ToolCall) model.PolicyDecision {
	ctx := context.Background()
	input := map[string]interface{}{
		"tool_name": toolCall.Name,
		"arguments": toolCall.Arguments,
		"raw_args":  toolCall.RawArgs,
	}

	decision := model.PolicyDecision{
		Timestamp: time.Now().UTC(),
		Action:    model.DecisionDeny,
		Reason:    "no policy allowed this tool",
	}

	results, err := e.prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return decision
	}

	for _, result := range results {
		for _, expr := range result.Expressions {
			val, ok := expr.Value.(map[string]interface{})
			if !ok {
				continue
			}

			// Check deny first (highest priority)
			if deny, ok := val["deny"].(bool); ok && deny {
				decision.Action = model.DecisionDeny
				decision.Reason = fmt.Sprintf("policy denied tool '%s'", toolCall.Name)
				return decision
			}
			if isTrueSet(val["deny"]) {
				decision.Action = model.DecisionDeny
				decision.Reason = fmt.Sprintf("policy denied tool '%s'", toolCall.Name)
				return decision
			}

			// Check log
			if logVal, ok := val["log"].(bool); ok && logVal {
				decision.Action = model.DecisionLog
				decision.PolicyName = "ghostguard"
				decision.Reason = fmt.Sprintf("policy logged tool '%s'", toolCall.Name)
				return decision
			}
			if isTrueSet(val["log"]) {
				decision.Action = model.DecisionLog
				decision.PolicyName = "ghostguard"
				decision.Reason = fmt.Sprintf("policy logged tool '%s'", toolCall.Name)
				return decision
			}

			// Check allow
			if allow, ok := val["allow"].(bool); ok && allow {
				decision.Action = model.DecisionAllow
				decision.PolicyName = "ghostguard"
				decision.Reason = fmt.Sprintf("policy allowed tool '%s'", toolCall.Name)
			}
			if isTrueSet(val["allow"]) {
				decision.Action = model.DecisionAllow
				decision.PolicyName = "ghostguard"
				decision.Reason = fmt.Sprintf("policy allowed tool '%s'", toolCall.Name)
			}
		}
	}

	return decision
}

func (e *Engine) PolicyCount() int {
	return len(e.modules)
}
