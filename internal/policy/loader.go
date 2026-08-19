package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func LoadPoliciesFromDir(dir string) (map[string]string, error) {
	policies := make(map[string]string)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading policy directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".rego") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading policy file %s: %w", path, err)
		}

		policies[entry.Name()] = string(content)
	}

	return policies, nil
}

func LoadPolicyFile(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading policy file %s: %w", path, err)
	}
	return string(content), nil
}
