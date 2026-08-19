package policy

import (
	"testing"

	"github.com/ghostguard/ghostguard/internal/model"
)

const testPolicy = `
package ghostguard

default allow = false

deny if {
    input.tool_name == "exec"
}

deny if {
    input.tool_name == "shell"
}

allow if {
    input.tool_name == "search_web"
}

allow if {
    input.tool_name == "get_weather"
}

log if {
    input.tool_name == "query_database"
}
`

func TestEngineDenyExec(t *testing.T) {
	eng := NewEngine()
	if err := eng.LoadPolicy("test.rego", testPolicy); err != nil {
		t.Fatalf("load policy: %v", err)
	}

	tc := &model.ToolCall{Name: "exec", Arguments: map[string]interface{}{"command": "ls"}}
	d := eng.Evaluate(tc)

	if d.Action != model.DecisionDeny {
		t.Errorf("expected deny, got %s", d.Action)
	}
}

func TestEngineDenyShell(t *testing.T) {
	eng := NewEngine()
	if err := eng.LoadPolicy("test.rego", testPolicy); err != nil {
		t.Fatalf("load policy: %v", err)
	}

	tc := &model.ToolCall{Name: "shell", Arguments: map[string]interface{}{"cmd": "whoami"}}
	d := eng.Evaluate(tc)

	if d.Action != model.DecisionDeny {
		t.Errorf("expected deny, got %s", d.Action)
	}
}

func TestEngineAllowSearchWeb(t *testing.T) {
	eng := NewEngine()
	if err := eng.LoadPolicy("test.rego", testPolicy); err != nil {
		t.Fatalf("load policy: %v", err)
	}

	tc := &model.ToolCall{Name: "search_web", Arguments: map[string]interface{}{"query": "golang"}}
	d := eng.Evaluate(tc)

	if d.Action != model.DecisionAllow {
		t.Errorf("expected allow, got %s", d.Action)
	}
}

func TestEngineAllowGetWeather(t *testing.T) {
	eng := NewEngine()
	if err := eng.LoadPolicy("test.rego", testPolicy); err != nil {
		t.Fatalf("load policy: %v", err)
	}

	tc := &model.ToolCall{Name: "get_weather", Arguments: map[string]interface{}{"city": "Madrid"}}
	d := eng.Evaluate(tc)

	if d.Action != model.DecisionAllow {
		t.Errorf("expected allow, got %s", d.Action)
	}
}

func TestEngineLogDatabase(t *testing.T) {
	eng := NewEngine()
	if err := eng.LoadPolicy("test.rego", testPolicy); err != nil {
		t.Fatalf("load policy: %v", err)
	}

	tc := &model.ToolCall{Name: "query_database", Arguments: map[string]interface{}{"sql": "SELECT * FROM users"}}
	d := eng.Evaluate(tc)

	if d.Action != model.DecisionLog {
		t.Errorf("expected log, got %s", d.Action)
	}
}

func TestEngineUnknownToolDefaultDeny(t *testing.T) {
	eng := NewEngine()
	if err := eng.LoadPolicy("test.rego", testPolicy); err != nil {
		t.Fatalf("load policy: %v", err)
	}

	tc := &model.ToolCall{Name: "random_unknown_tool", Arguments: map[string]interface{}{}}
	d := eng.Evaluate(tc)

	if d.Action != model.DecisionDeny {
		t.Errorf("expected deny for unknown tool, got %s", d.Action)
	}
}

func TestEngineMultiplePolicies(t *testing.T) {
	eng := NewEngine()

	p1 := `
package ghostguard
deny if { input.tool_name == "rm" }
`
	p2 := `
package ghostguard
allow if { input.tool_name == "ls" }
`

	if err := eng.LoadPolicy("p1.rego", p1); err != nil {
		t.Fatalf("load p1: %v", err)
	}
	if err := eng.LoadPolicy("p2.rego", p2); err != nil {
		t.Fatalf("load p2: %v", err)
	}

	if eng.PolicyCount() != 2 {
		t.Errorf("expected 2 policies, got %d", eng.PolicyCount())
	}

	d1 := eng.Evaluate(&model.ToolCall{Name: "rm", Arguments: map[string]interface{}{}})
	if d1.Action != model.DecisionDeny {
		t.Errorf("rm: expected deny, got %s", d1.Action)
	}

	d2 := eng.Evaluate(&model.ToolCall{Name: "ls", Arguments: map[string]interface{}{}})
	if d2.Action != model.DecisionAllow {
		t.Errorf("ls: expected allow, got %s", d2.Action)
	}
}

func TestEngineInvalidPolicy(t *testing.T) {
	eng := NewEngine()
	err := eng.LoadPolicy("bad.rego", "this is not valid rego {{{")
	if err == nil {
		t.Error("expected error for invalid policy")
	}
}

func TestEngineEmptyPolicy(t *testing.T) {
	eng := NewEngine()
	err := eng.LoadPolicy("empty.rego", "")
	if err == nil {
		t.Fatal("expected error for empty policy")
	}
	// Empty rego is invalid; engine should have 0 policies
	if eng.PolicyCount() != 0 {
		t.Errorf("expected 0 policies after failed load, got %d", eng.PolicyCount())
	}
}

func TestEnginePolicyWithArguments(t *testing.T) {
	eng := NewEngine()

	policy := `
package ghostguard
default allow = false

deny if {
    input.tool_name == "exec"
    input.arguments.command == "rm -rf /"
}
`
	if err := eng.LoadPolicy("args.rego", policy); err != nil {
		t.Fatalf("load policy: %v", err)
	}

	d1 := eng.Evaluate(&model.ToolCall{
		Name:      "exec",
		Arguments: map[string]interface{}{"command": "rm -rf /"},
	})
	if d1.Action != model.DecisionDeny {
		t.Errorf("rm -rf /: expected deny, got %s", d1.Action)
	}

	d2 := eng.Evaluate(&model.ToolCall{
		Name:      "exec",
		Arguments: map[string]interface{}{"command": "ls"},
	})
	if d2.Action != model.DecisionDeny {
		t.Errorf("ls: expected deny (default), got %s", d2.Action)
	}
}
