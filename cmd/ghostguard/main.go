package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ghostguard/ghostguard/internal/mcp"
	"github.com/ghostguard/ghostguard/internal/model"
	"github.com/ghostguard/ghostguard/internal/policy"
	"github.com/ghostguard/ghostguard/internal/proxy"
)

var version = "v0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "policy":
		cmdPolicy(os.Args[2:])
	case "config":
		cmdConfig(os.Args[2:])
	case "mcp":
		cmdMCP()
	case "version":
		fmt.Printf("ghostguard %s\n", version)
	case "status":
		cmdStatus()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `GhostGuard — AI Agent Security Proxy

Usage:
  ghostguard serve [flags]      Start the proxy server
  ghostguard policy test        Test a policy against input
  ghostguard policy lint        Lint .rego policy files
  ghostguard config init        Generate default config.yaml
  ghostguard mcp                Run as MCP stdio server
  ghostguard status             Show proxy status
  ghostguard version            Print version

Examples:
  ghostguard serve --port 8081 --policies ./policies
  ghostguard serve --dry-run --port 8081
  ghostguard policy test --policy policy.rego --tool exec --args '{"command":"ls"}'
  ghostguard config init
  ghostguard mcp
`)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configFile := fs.String("config", "config.yaml", "Config file path")
	port := fs.String("port", "", "Listen port (overrides config)")
	dashPort := fs.String("dash-port", "", "Dashboard port (empty to disable, overrides config)")
	policyDir := fs.String("policies", "", "Policy directory (overrides config)")
	auditLog := fs.String("audit-log", "", "Audit log file path (overrides config)")
	webhook := fs.String("webhook", "", "Alert webhook URL (overrides config)")
	slack := fs.String("slack", "", "Slack webhook URL (overrides config)")
	dryRun := fs.Bool("dry-run", false, "Dry-run mode: evaluate but don't enforce (overrides config)")
	rateLimit := fs.Int("rate-limit", 0, "Max tool calls per minute per host (overrides config)")
	rateWindow := fs.Duration("rate-window", 0, "Rate limit window (overrides config)")
	rateThreshold := fs.Float64("rate-threshold", 0, "Rate anomaly Z-score threshold (overrides config)")
	entropyThreshold := fs.Float64("entropy-threshold", 0, "Entropy anomaly threshold (overrides config)")

	fs.Parse(args)

	cfg, err := proxy.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	overrides := proxy.Config{}
	if *port != "" {
		overrides.ListenAddr = ":" + *port
	}
	if *dashPort != "" {
		overrides.DashAddr = ":" + *dashPort
	}
	if *policyDir != "" {
		overrides.PolicyDir = *policyDir
	}
	if *auditLog != "" {
		overrides.AuditLogPath = *auditLog
	}
	if *webhook != "" {
		overrides.AlertWebhook = *webhook
	}
	if *slack != "" {
		overrides.SlackWebhook = *slack
	}
	if *dryRun {
		overrides.DryRun = true
	}
	if *rateLimit > 0 {
		overrides.RateLimit = *rateLimit
	}
	if *rateWindow > 0 {
		overrides.RateWindow = *rateWindow
	}
	if *rateThreshold > 0 {
		overrides.Detector.RateThreshold = *rateThreshold
	}
	if *entropyThreshold > 0 {
		overrides.Detector.EntropyThreshold = *entropyThreshold
	}

	cfg = proxy.MergeConfig(cfg, overrides)

	p, err := proxy.New(cfg)
	if err != nil {
		log.Fatalf("failed to create proxy: %v", err)
	}

	if err := p.LoadPolicies(cfg.PolicyDir); err != nil {
		log.Printf("warning: failed to load policies from %s: %v", cfg.PolicyDir, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nshutting down...")
		cancel()
		p.Shutdown(context.Background())
	}()

	fmt.Printf("GhostGuard proxy listening on %s\n", cfg.ListenAddr)
	if cfg.DashAddr != "" {
		fmt.Printf("Dashboard: http://localhost%s\n", cfg.DashAddr)
	}
	fmt.Printf("Targeting: %v\n", cfg.TargetHosts)
	if cfg.DryRun {
		fmt.Println("Mode: DRY-RUN (policies evaluated, not enforced)")
	}
	fmt.Printf("Rate limit: %d calls/%v per host\n", cfg.RateLimit, cfg.RateWindow)

	if err := p.StartContext(ctx); err != nil && err != context.Canceled {
		log.Fatalf("proxy error: %v", err)
	}
}

func cmdPolicy(args []string) {
	fs := flag.NewFlagSet("policy", flag.ExitOnError)
	fs.Parse(args)

	if len(fs.Args()) < 1 {
		fmt.Fprintf(os.Stderr, "usage: ghostguard policy <test|lint> [flags]\n")
		os.Exit(1)
	}

	switch fs.Args()[0] {
	case "test":
		cmdPolicyTest(fs.Args()[1:])
	case "lint":
		cmdPolicyLint(fs.Args()[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown policy subcommand: %s\n", fs.Args()[0])
		os.Exit(1)
	}
}

func cmdPolicyTest(args []string) {
	fs := flag.NewFlagSet("policy test", flag.ExitOnError)
	policyFile := fs.String("policy", "", "Policy file (.rego)")
	inputFile := fs.String("input", "", "Input JSON file")
	toolName := fs.String("tool", "", "Tool name (quick test)")
	toolArgs := fs.String("args", "{}", "Tool arguments JSON")

	fs.Parse(args)

	if *policyFile == "" {
		fmt.Fprintf(os.Stderr, "error: --policy flag required\n")
		os.Exit(1)
	}

	content, err := os.ReadFile(*policyFile)
	if err != nil {
		log.Fatalf("failed to read policy: %v", err)
	}

	eng := policy.NewEngine()
	if err := eng.LoadPolicy(*policyFile, string(content)); err != nil {
		log.Fatalf("failed to load policy: %v", err)
	}

	var toolCall model.ToolCall

	if *inputFile != "" {
		inputData, err := os.ReadFile(*inputFile)
		if err != nil {
			log.Fatalf("failed to read input: %v", err)
		}
		if err := json.Unmarshal(inputData, &toolCall); err != nil {
			log.Fatalf("failed to parse input: %v", err)
		}
	} else if *toolName != "" {
		toolCall.Name = *toolName
		var args map[string]interface{}
		json.Unmarshal([]byte(*toolArgs), &args)
		toolCall.Arguments = args
		toolCall.RawArgs = *toolArgs
	} else {
		fmt.Fprintf(os.Stderr, "error: --input or --tool flag required\n")
		os.Exit(1)
	}

	decision := eng.Evaluate(&toolCall)

	output, _ := json.MarshalIndent(decision, "", "  ")
	fmt.Println(string(output))

	if decision.Action == model.DecisionDeny {
		os.Exit(1)
	}
}

func cmdPolicyLint(args []string) {
	fs := flag.NewFlagSet("policy lint", flag.ExitOnError)
	dir := fs.String("dir", ".", "Directory with .rego files")
	fs.Parse(args)

	policies, err := policy.LoadPoliciesFromDir(*dir)
	if err != nil {
		log.Fatalf("failed to read directory: %v", err)
	}

	eng := policy.NewEngine()
	errors := 0

	for name, content := range policies {
		if err := eng.LoadPolicy(name, content); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", name, err)
			errors++
		} else {
			fmt.Printf("OK: %s\n", name)
		}
	}

	if errors > 0 {
		fmt.Fprintf(os.Stderr, "\n%d policy file(s) with errors\n", errors)
		os.Exit(1)
	}

	fmt.Printf("\n%d policy file(s) OK\n", len(policies))
}

func cmdConfig(args []string) {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	fs.Parse(args)

	if len(fs.Args()) < 1 || fs.Args()[0] != "init" {
		fmt.Fprintf(os.Stderr, "usage: ghostguard config init\n")
		os.Exit(1)
	}

	defaultConfig := `# GhostGuard Configuration
listen_addr: ":8081"
dash_addr: ":9090"
policy_dir: "./policies"
target_hosts:
  - api.openai.com
  - api.anthropic.com
  - generativelanguage.googleapis.com
alert_webhook: ""
slack_webhook: ""
audit_log_path: ""
dry_run: false
rate_limit: 60
rate_window: "1m"
detector:
  rate_threshold: 3.0
  entropy_threshold: 4.0
  window_interval: "1m"
  window_max_age: "5m"
  max_prev_tools: 10
`

	if err := os.WriteFile("config.yaml", []byte(defaultConfig), 0644); err != nil {
		log.Fatalf("failed to write config: %v", err)
	}
	fmt.Println("Created config.yaml")
}

func cmdMCP() {
	mcp.RunMCPFromMain()
}

func cmdStatus() {
	fmt.Printf("GhostGuard %s\n", version)
	fmt.Println("Status: not running (standalone check)")
	fmt.Println("")
	fmt.Println("To start: ghostguard serve --port 8081 --policies ./policies")
	fmt.Println("Dashboard: http://localhost:9090")
}
