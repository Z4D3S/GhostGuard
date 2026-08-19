package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ghostguard/ghostguard/internal/alert"
	"github.com/ghostguard/ghostguard/internal/audit"
	"github.com/ghostguard/ghostguard/internal/dashboard"
	"github.com/ghostguard/ghostguard/internal/detector"
	"github.com/ghostguard/ghostguard/internal/policy"
	"gopkg.in/yaml.v3"
)

type Proxy struct {
	server      *http.Server
	dashServer  *http.Server
	config      Config
	engine      *policy.Engine
	detector    *detector.Detector
	rateLimiter *detector.RateLimiter
	alertMgr    *alert.Manager
	logger      *audit.Logger
	certMgr     *CertManager
	dash        *dashboard.Dashboard
	stopCh      chan struct{}
}

type Config struct {
	ListenAddr   string        `yaml:"listen_addr"`
	DashAddr     string        `yaml:"dash_addr"`
	PolicyDir    string        `yaml:"policy_dir"`
	TargetHosts  []string      `yaml:"target_hosts"`
	AlertWebhook string        `yaml:"alert_webhook"`
	SlackWebhook string        `yaml:"slack_webhook"`
	AuditLogPath string        `yaml:"audit_log_path"`
	DryRun       bool          `yaml:"dry_run"`
	RateLimit    int           `yaml:"rate_limit"`
	RateWindow   time.Duration `yaml:"rate_window"`
	Detector     detector.DetectorConfig `yaml:"detector"`
	BaselinePath string        `yaml:"baseline_path"`
}

func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("reading config file: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing config file: %w", err)
	}
	return cfg, nil
}

func MergeConfig(base Config, overrides Config) Config {
	if overrides.ListenAddr != "" {
		base.ListenAddr = overrides.ListenAddr
	}
	if overrides.DashAddr != "" {
		base.DashAddr = overrides.DashAddr
	}
	if overrides.PolicyDir != "" {
		base.PolicyDir = overrides.PolicyDir
	}
	if len(overrides.TargetHosts) > 0 {
		base.TargetHosts = overrides.TargetHosts
	}
	if overrides.AlertWebhook != "" {
		base.AlertWebhook = overrides.AlertWebhook
	}
	if overrides.SlackWebhook != "" {
		base.SlackWebhook = overrides.SlackWebhook
	}
	if overrides.AuditLogPath != "" {
		base.AuditLogPath = overrides.AuditLogPath
	}
	if overrides.DryRun {
		base.DryRun = overrides.DryRun
	}
	if overrides.RateLimit != 0 {
		base.RateLimit = overrides.RateLimit
	}
	if overrides.RateWindow != 0 {
		base.RateWindow = overrides.RateWindow
	}
	if overrides.Detector.RateThreshold != 0 {
		base.Detector.RateThreshold = overrides.Detector.RateThreshold
	}
	if overrides.Detector.EntropyThreshold != 0 {
		base.Detector.EntropyThreshold = overrides.Detector.EntropyThreshold
	}
	if overrides.BaselinePath != "" {
		base.BaselinePath = overrides.BaselinePath
	}
	return base
}

func DefaultConfig() Config {
	return Config{
		ListenAddr:  ":8081",
		DashAddr:    ":9090",
		TargetHosts: []string{"api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com"},
		RateLimit:   60,
		RateWindow:  time.Minute,
		Detector:    detector.DefaultConfig(),
	}
}

func New(cfg Config) (*Proxy, error) {
	certMgr, err := NewCertManager()
	if err != nil {
		return nil, fmt.Errorf("creating cert manager: %w", err)
	}

	eng := policy.NewEngine()
	det := detector.NewDetector(cfg.Detector)
	rateLimiter := detector.NewRateLimiter(cfg.RateLimit, cfg.RateWindow)

	var sinks []alert.Sink
	sinks = append(sinks, alert.NewStdoutSink(log.Writer()))
	if cfg.AlertWebhook != "" {
		sinks = append(sinks, alert.NewWebhookSink(cfg.AlertWebhook))
	}
	if cfg.SlackWebhook != "" {
		sinks = append(sinks, alert.NewSlackSink(cfg.SlackWebhook, "#ghostguard"))
	}
	alertMgr := alert.NewManager(sinks...)

	var auditLogger *audit.Logger
	if cfg.AuditLogPath != "" {
		auditLogger, err = audit.NewFileLogger(cfg.AuditLogPath)
		if err != nil {
			return nil, fmt.Errorf("creating audit logger: %w", err)
		}
	} else {
		auditLogger = audit.NewLogger(log.Writer())
	}

	dash := dashboard.NewDashboard()

	p := &Proxy{
		config:      cfg,
		engine:      eng,
		detector:    det,
		rateLimiter: rateLimiter,
		alertMgr:    alertMgr,
		logger:      auditLogger,
		certMgr:     certMgr,
		dash:        dash,
		stopCh:      make(chan struct{}),
	}

	p.server = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      p,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if cfg.DashAddr != "" {
		p.dashServer = &http.Server{
			Addr:    cfg.DashAddr,
			Handler: dash,
		}
	}

	return p, nil
}

func (p *Proxy) Start() error {
	return p.StartContext(context.Background())
}

func (p *Proxy) StartContext(ctx context.Context) error {
	p.logger.LogMessage("info", fmt.Sprintf("GhostGuard proxy starting on %s", p.config.ListenAddr))
	p.logger.LogMessage("info", fmt.Sprintf("Policies loaded: %d", p.engine.PolicyCount()))
	if p.config.DryRun {
		p.logger.LogMessage("info", "DRY-RUN mode: policies evaluated but not enforced")
	}

	if err := p.certMgr.ExportCA("ghostguard-ca.pem"); err != nil {
		p.logger.LogMessage("warn", fmt.Sprintf("could not export CA: %v", err))
	} else {
		p.logger.LogMessage("info", "CA certificate exported to ghostguard-ca.pem")
	}

	if p.dashServer != nil {
		go func() {
			p.logger.LogMessage("info", fmt.Sprintf("Dashboard on http://localhost%s", p.config.DashAddr))
			if err := p.dashServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				p.logger.LogMessage("error", fmt.Sprintf("dashboard error: %v", err))
			}
		}()
	}

	listener, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.config.ListenAddr, err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.server.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		p.Shutdown(context.Background())
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (p *Proxy) Shutdown(ctx context.Context) error {
	close(p.stopCh)
	if p.dashServer != nil {
		p.dashServer.Shutdown(ctx)
	}
	return p.server.Shutdown(ctx)
}

func (p *Proxy) LoadPolicies(dir string) error {
	policies, err := policy.LoadPoliciesFromDir(dir)
	if err != nil {
		return err
	}

	for name, content := range policies {
		if err := p.engine.LoadPolicy(name, content); err != nil {
			return fmt.Errorf("loading policy %s: %w", name, err)
		}
		p.logger.LogMessage("info", fmt.Sprintf("loaded policy: %s", name))
	}

	go p.watchPolicies(dir)
	return nil
}

func (p *Proxy) watchPolicies(dir string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	lastModTimes := make(map[string]time.Time)
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".rego") {
				info, err := entry.Info()
				if err == nil {
					lastModTimes[entry.Name()] = info.ModTime()
				}
			}
		}
	}

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}

			newFiles := make(map[string]bool)
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rego") {
					continue
				}
				newFiles[entry.Name()] = true

				info, err := entry.Info()
				if err != nil {
					continue
				}

				lastMod, exists := lastModTimes[entry.Name()]
				if !exists || info.ModTime().After(lastMod) {
					path := filepath.Join(dir, entry.Name())
					content, err := os.ReadFile(path)
					if err != nil {
						continue
					}
					if err := p.engine.LoadPolicy(entry.Name(), string(content)); err != nil {
						p.logger.LogMessage("error", fmt.Sprintf("reloading policy %s: %v", entry.Name(), err))
						continue
					}
					p.logger.LogMessage("info", fmt.Sprintf("reloaded policy: %s", entry.Name()))
					lastModTimes[entry.Name()] = info.ModTime()
				}
			}

			for name := range lastModTimes {
				if !newFiles[name] {
					delete(lastModTimes, name)
					p.logger.LogMessage("info", fmt.Sprintf("policy removed: %s", name))
				}
			}
		}
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1") {
		if r.URL.Path == "/ghostguard" || strings.HasPrefix(r.URL.Path, "/ghostguard/") {
			p.dash.ServeHTTP(w, r)
			return
		}
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

var _ http.Handler = (*Proxy)(nil)
