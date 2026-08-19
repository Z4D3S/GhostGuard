package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPoliciesFromDir(t *testing.T) {
	dir := t.TempDir()

	policy1 := `package ghostguard
default allow = false
allow if { input.tool_name == "search" }`

	policy2 := `package ghostguard
deny if { input.tool_name == "exec" }`

	os.WriteFile(filepath.Join(dir, "allow.rego"), []byte(policy1), 0644)
	os.WriteFile(filepath.Join(dir, "deny.rego"), []byte(policy2), 0644)

	policies, err := LoadPoliciesFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}
	if _, ok := policies["allow.rego"]; !ok {
		t.Error("expected allow.rego in policies")
	}
	if _, ok := policies["deny.rego"]; !ok {
		t.Error("expected deny.rego in policies")
	}
}

func TestLoadPoliciesFromDirSkipsNonRego(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "policy.rego"), []byte("package ghostguard"), 0644)
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a policy"), 0644)
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("not a policy"), 0644)

	policies, err := LoadPoliciesFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(policies))
	}
}

func TestLoadPoliciesFromDirSkipsDirs(t *testing.T) {
	dir := t.TempDir()

	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
	os.WriteFile(filepath.Join(dir, "policy.rego"), []byte("package ghostguard"), 0644)

	policies, err := LoadPoliciesFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(policies))
	}
}

func TestLoadPoliciesFromDirNonExistent(t *testing.T) {
	_, err := LoadPoliciesFromDir("/nonexistent/path")
	if err == nil {
		t.Error("expected error for non-existent directory")
	}
}

func TestLoadPolicyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.rego")

	content := `package ghostguard
allow if { input.tool_name == "test" }`

	os.WriteFile(path, []byte(content), 0644)

	loaded, err := LoadPolicyFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if loaded != content {
		t.Errorf("loaded content mismatch")
	}
}

func TestLoadPolicyFileNonExistent(t *testing.T) {
	_, err := LoadPolicyFile("/nonexistent/file.rego")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}
