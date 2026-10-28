package cli

import (
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/xihale/snirect/internal/cert"
	"github.com/xihale/snirect/internal/config"
	"github.com/xihale/snirect/internal/dns"
	"github.com/xihale/snirect/internal/logger"
	"github.com/xihale/snirect/internal/proxy"
	"github.com/xihale/snirect/internal/rules"
	"github.com/xihale/snirect/internal/sysproxy"

	"github.com/spf13/cobra"
)

// ProxyEnv holds a bootstrapped proxy ready to run, shared by the bare
// `snirect` entrypoint via RunProxy. The owner calls Cleanup when done.
type ProxyEnv struct {
	Cfg     *config.Config
	AppDir  string
	certMgr *cert.CertificateManager
	// resolver is the shared resolver behind both the proxy and the upstream
	// client; closed in Cleanup.
	resolver *dns.Resolver
	Server   proxyServer
	// pacSet is true if this process programmed the system PAC. Only the main
	// goroutine touches it (set before serving, read in Cleanup after serving
	// ends), so it needs no lock. This fixes the old predicate that gated
	// cleanup on the --set-proxy flag.
	pacSet bool
}

// Cleanup clears the system PAC iff this process set it, then closes the
// resolver and certificate manager.
func (env *ProxyEnv) Cleanup() {
	if env.pacSet {
		sysproxy.ClearPAC()
	}
	if env.resolver != nil {
		env.resolver.Close()
	}
	if env.certMgr != nil {
		env.certMgr.Close()
	}
}

// proxyServer is the subset of *proxy.ProxyServer the lifecycle uses. Extracted
// as an interface so tests can substitute a fake.
type proxyServer interface {
	Listen() error
	Serve() error
	Shutdown(ctx context.Context) error
}

// RunOptions configures RunProxy. Today the only option is OnReady; the type
// is kept so callers can grow it without touching RunProxy's signature.
type RunOptions struct {
	OnReady func(port int)
}

// BootstrapProxy performs the shared startup preparation: load config, build
// the resolver + CA + proxy server. It does NOT start serving. On error any
// partial state is cleaned up.
func BootstrapProxy(cmd *cobra.Command) (*ProxyEnv, error) {
	cfg, appDir, err := loadAppConfig()
	if err != nil {
		return nil, err
	}

	cd := certDir(appDir)
	if err := os.MkdirAll(cd, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create cert dir: %w", err)
	}

	setupLogging(cfg, cmd)
	startPprof()

	r, err := rules.LoadRules()
	if err != nil {
		logger.Control().Warn("failed to load rules", "error", err)
	}

	cm, err := cert.NewCertificateManager(certPath(appDir), filepath.Join(cd, "root.key"))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize CA: %w", err)
	}

	installCA(cfg, appDir)

	resolver := dns.NewResolver(cfg, r)
	srv := proxy.NewProxyServer(cfg, r, cm, resolver)

	return &ProxyEnv{Cfg: cfg, AppDir: appDir, certMgr: cm, resolver: resolver, Server: srv}, nil
}

// RunProxy is the entrypoint for the proxy command.
func RunProxy(cmd *cobra.Command, opts RunOptions) error {
	cfg, appDir, err := loadAppConfig()
	if err != nil {
		return err
	}

	caPolicy := cfg.GetCAInstall()
	activeMode := cfg.GetMode()
	if setProxyMode != "" && setProxyMode != "default" {
		activeMode = strings.ToLower(setProxyMode)
	}

	// Residuals are ONLY checked and prompted if ca_install is "conservative"
	if caPolicy == "conservative" {
		if err := PromptAndCleanResiduals(appDir, activeMode, forceClean); err != nil {
			return err
		}
	}

	cd := certDir(appDir)
	if err := os.MkdirAll(cd, 0o700); err != nil {
		return fmt.Errorf("failed to create cert dir: %w", err)
	}

	setupLogging(cfg, cmd)
	startPprof()

	r, err := rules.LoadRules()
	if err != nil {
		logger.Control().Warn("failed to load rules", "error", err)
	}

	// In conservative mode, wipe the local certs directory on start to guarantee a fresh ephemeral CA.
	// In auto, always, or never modes, existing certificates are preserved.
	if caPolicy == "conservative" {
		_ = os.RemoveAll(cd)
		_ = os.MkdirAll(cd, 0o700)
	}

	// Always generate or load the CA, as the local proxy engine requires it for TLS interception.
	cm, err := cert.NewCertificateManager(certPath(appDir), filepath.Join(cd, "root.key"))
	if err != nil {
		return fmt.Errorf("failed to initialize CA: %w", err)
	}

	// Write SPKI hash file
	spkiHash, err := cm.GetSPKIHash()
	if err == nil {
		_ = os.WriteFile(filepath.Join(appDir, "spki_hash.txt"), []byte(spkiHash), 0644)
	}

	resolver := dns.NewResolver(cfg, r)
	srv := proxy.NewProxyServer(cfg, r, cm, resolver)

	env := &ProxyEnv{Cfg: cfg, AppDir: appDir, certMgr: cm, resolver: resolver, Server: srv}

	// Defer cleanup hook: ONLY delete certificates (local folder & system/Firefox store)
	// when ca_install is "conservative".
	defer func() {
		logger.Control().Info("shutting down proxy")
		env.Cleanup()
		if caPolicy == "conservative" {
			CleanAllResiduals(appDir, activeMode)
		}
	}()

	if err := env.Server.Listen(); err != nil {
		return err
	}
	port := env.Cfg.Server.Port

	// Apply mode when -s flag is provided
	if setProxyMode != "" {
		switch activeMode {
		case "sysproxy":
			if caPolicy != "never" {
				installCA(cfg, appDir)
			} else {
				logger.Control().Info("sysproxy mode active: CA installation skipped (ca_install=never)")
			}
			sysproxy.SetPAC(pacURL("127.0.0.1", port))
			env.pacSet = true
			fmt.Printf("System proxy mode active. PAC set to port %d\n", port)

		case "chromium":
			binPath, err := FindChromiumPath(resolveChromiumPath(cfg))
			if err != nil {
				return err
			}
			// In "never" mode, do NOT pass SPKI parameter to Chromium
			trustSPKI := (caPolicy != "never")
			if trustSPKI {
				fmt.Printf("Launching Chromium browser with SPKI sandbox (hash: %s)...\n", spkiHash)
			} else {
				fmt.Println("Launching Chromium browser without SPKI trust parameter (ca_install=never)...")
			}
			if _, err := LaunchChromium(binPath, port, spkiHash, appDir, trustSPKI); err != nil {
				return err
			}

		case "firefox":
			if caPolicy != "never" {
				if err := sysproxy.InstallFirefoxCert(certPath(appDir)); err != nil {
					logger.Control().Warn("failed to install cert to Firefox profiles", "error", err)
				}
			} else {
				logger.Control().Info("firefox mode active: CA installation skipped (ca_install=never)")
			}
			binPath, err := FindFirefoxPath(resolveFirefoxPath(cfg))
			if err == nil {
				fmt.Println("Launching Firefox browser...")
				_, _ = LaunchFirefox(binPath)
			} else {
				fmt.Println("Firefox cert configured. Manual browser launch required.")
			}

		default:
			return fmt.Errorf("unsupported mode: %s (choose sysproxy, chromium, or firefox)", activeMode)
		}
	}

	if opts.OnReady != nil {
		opts.OnReady(port)
	}

	proxyErr := make(chan error, 1)
	go func() { proxyErr <- env.Server.Serve() }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	var runErr error
	select {
	case err := <-proxyErr:
		runErr = fmt.Errorf("proxy failed: %w", err)
	case <-sig:
		logger.Control().Info("received termination signal")
	}

	sctx, scancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer scancel()
	_ = env.Server.Shutdown(sctx)
	return runErr
}

func resolveChromiumPath(cfg *config.Config) string {
	if chromiumPathFlag != "" {
		return chromiumPathFlag
	}
	return cfg.ChromiumPath
}

func resolveFirefoxPath(cfg *config.Config) string {
	if firefoxPathFlag != "" {
		return firefoxPathFlag
	}
	return cfg.FirefoxPath
}

func setupLogging(cfg *config.Config, cmd *cobra.Command) {
	level := cfg.Log.Level
	if logLevel != "" {
		level = logLevel
	}
	logger.SetLevel(level)

	if cfg.Log.File != "" {
		logPath := cfg.Log.File
		if !filepath.IsAbs(logPath) {
			appDir, _ := config.GetAppDataDir()
			logPath = filepath.Join(appDir, logPath)
		}
		if err := logger.SetOutput(logPath); err != nil {
			fmt.Fprintf(os.Stderr, "failed to set log file: %v\n", err)
		} else {
			logger.Control().Info("log file configured", "path", logPath)
		}
	}
}

func startPprof() {
	if !pprof {
		return
	}
	go func() {
		logger.Control().Info("pprof listening", "addr", pprofAddr)
		if err := http.ListenAndServe(pprofAddr, nil); err != nil {
			logger.Control().Error("pprof failed", "error", err)
		}
	}()
}

func installCA(cfg *config.Config, appDir string) {
	p := certPath(appDir)
	if cfg.CAInstall == "never" {
		logger.Control().Info("CA auto-install disabled")
		return
	}

	// systemd units have no TTY. sudo then fails with "需要密码" (and run0
	// would stall on polkit). Skip; `snirect cert install` is the interactive path.
	if skipPrivilegedCAInstall() {
		installed, err := sysproxy.CheckCertStatus(p)
		if err != nil || !installed {
			logger.Control().Warn("CA not in system trust store; skipping install under systemd (cannot prompt for sudo). Run once: snirect cert install")
		}
		return
	}

	if cfg.CAInstall == "always" {
		installed, err := sysproxy.ForceInstallCert(p)
		if err != nil {
			logger.Control().Warn("CA install failed", "error", err)
		} else if installed {
			logger.Control().Info("CA reinstalled")
		}
		return
	}

	installed, err := sysproxy.InstallCert(p)
	if err != nil {
		logger.Control().Warn("CA install failed", "error", err)
	} else if installed {
		logger.Control().Info("CA installed")
	}
}

// skipPrivilegedCAInstall is true for a systemd unit that is not root.
// INVOCATION_ID is set by systemd for every unit, including --user services.
func skipPrivilegedCAInstall() bool {
	return os.Getenv("INVOCATION_ID") != "" && os.Geteuid() != 0
}

func shouldSetProxy(cmd *cobra.Command, cfg *config.Config) bool {
	if cmd.Flags().Changed("set-proxy") {
		return setProxyMode != ""
	}
	return cfg.SetProxy
}
