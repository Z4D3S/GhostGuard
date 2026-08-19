package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ghostguard/ghostguard/internal/alert"
	"github.com/ghostguard/ghostguard/internal/audit"
	"github.com/ghostguard/ghostguard/internal/dashboard"
	"github.com/ghostguard/ghostguard/internal/detector"
	"github.com/ghostguard/ghostguard/internal/policy"
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
}

type Config struct {
	ListenAddr   string
	DashAddr     string
	PolicyDir    string
	TargetHosts  []string
	AlertWebhook string
	SlackWebhook string
	AuditLogPath string
	DryRun       bool
	RateLimit    int
	RateWindow   time.Duration
	Detector     detector.DetectorConfig
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

	return p.server.Serve(listener)
}

func (p *Proxy) Shutdown(ctx context.Context) error {
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
	return nil
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
