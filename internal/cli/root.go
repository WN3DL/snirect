package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	setProxyMode     string
	chromiumPathFlag string
	firefoxPathFlag  string
	forceClean       bool
	logLevel         string
	pprof            bool
	pprofAddr        string
)

var rootCmd = &cobra.Command{
	Use:   "snirect",
	Short: "Cross-platform SNI proxy for bypassing censorship",
	Long: `Snirect is a transparent HTTP/HTTPS proxy that modifies SNI
(Server Name Indication) to bypass SNI-based censorship.

Supports: Linux, macOS, Windows`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunProxy(cmd, RunOptions{
			OnReady: func(port int) {
				fmt.Printf("\nSnirect running on port %d\n", port)
				fmt.Printf("Press Ctrl+C to stop and clean up certificates.\n\n")
			},
		})
	},
}

func init() {
	// -s flag accepts optional mode argument: "sysproxy", "chromium", "firefox"
	rootCmd.Flags().StringVarP(&setProxyMode, "set-proxy", "s", "", "Enable proxy with mode (sysproxy, chromium, firefox). Defaults to config if no mode passed.")
	rootCmd.Flags().Lookup("set-proxy").NoOptDefVal = "default"

	rootCmd.Flags().StringVar(&chromiumPathFlag, "chromium-path", "", "Custom executable path for Chromium/Chrome/Edge")
	rootCmd.Flags().StringVar(&firefoxPathFlag, "firefox-path", "", "Custom executable path for Firefox")
	rootCmd.Flags().BoolVar(&forceClean, "force-clean", false, "Force clean residual certificates without interactive prompt")

	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "v", "", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().BoolVar(&pprof, "pprof", false, "Enable pprof profiling")
	rootCmd.PersistentFlags().StringVar(&pprofAddr, "pprof-addr", "127.0.0.1:6060", "pprof listen address")

	certCmd.AddCommand(certInstallCmd, certRemoveCmd, certStatusCmd)
	certCmd.AddCommand(firefoxCertCmd)
	firefoxCertCmd.AddCommand(firefoxInstallCmd, firefoxRemoveCmd, firefoxStatusCmd)

	proxyCmd.AddCommand(proxySetCmd, proxyUnsetCmd, proxyEnvCmd)
	configCmd.AddCommand(configResetCmd)

	rulesDAECmd.Flags().StringVar(&rulesDAEPolicy, "policy", "snirect", "dae group the rules point to")
	rulesClashCmd.Flags().StringVar(&rulesClashPolicy, "policy", "snirect", "clash policy the rules point to")
	rulesCmd.AddCommand(rulesDAECmd, rulesClashCmd)

	// installCmd, uninstallCmd, and statusCmd are completely removed for clean portable usage
	rootCmd.AddCommand(
		certCmd,
		proxyCmd,
		configCmd,
		rulesCmd,
		versionCmd,
		updateCmd,
		completionCmd,
	)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
