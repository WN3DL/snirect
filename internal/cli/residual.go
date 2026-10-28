package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/xihale/snirect/internal/logger"
	"github.com/xihale/snirect/internal/sysproxy"
)

// CheckResiduals checks for leftover certificates in the selected mode and certs folder.
func CheckResiduals(appDir, mode string) (bool, string) {
	var reasons []string

	// Check local certs folder
	cd := certDir(appDir)
	if entries, err := os.ReadDir(cd); err == nil && len(entries) > 0 {
		reasons = append(reasons, fmt.Sprintf("local certs directory (%s)", cd))
	}

	// Check mode-specific external residuals
	switch strings.ToLower(mode) {
	case "sysproxy":
		if runtime.GOOS == "windows" {
			cmd := exec.Command("certutil", "-user", "-verifystore", "Root", "Snirect Root CA")
			if err := cmd.Run(); err == nil {
				reasons = append(reasons, "system root certificate store")
			}
		}
	case "firefox":
		installed, err := sysproxy.CheckFirefoxCert()
		if err == nil && installed {
			reasons = append(reasons, "Firefox NSS certificate database")
		}
	case "chromium":
		// Chromium mode never installs certificates to the operating system.
	}

	if len(reasons) > 0 {
		return true, strings.Join(reasons, ", ")
	}
	return false, ""
}

// PromptAndCleanResiduals prompts the user (Y/n, defaults to Y) or cleans immediately if forceClean is set.
func PromptAndCleanResiduals(appDir, mode string, forceClean bool) error {
	hasResiduals, details := CheckResiduals(appDir, mode)
	if !hasResiduals {
		return nil
	}

	fmt.Printf("\n[!] Residual certificates detected in: %s\n", details)

	if !forceClean {
		fmt.Print("Do you want to clean up residual certificates? [Y/n]: ")
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read user input: %w", err)
		}
		input = strings.TrimSpace(strings.ToLower(input))
		if input != "" && input != "y" && input != "yes" {
			fmt.Println("Residual cleanup skipped.")
			return nil
		}
	}

	fmt.Println("Cleaning up residual certificates...")
	CleanAllResiduals(appDir, mode)
	fmt.Println("Residual cleanup completed.")
	return nil
}

// CleanAllResiduals wipes certificates from the mode and the local folder.
func CleanAllResiduals(appDir, mode string) {
	switch strings.ToLower(mode) {
	case "sysproxy":
		if runtime.GOOS == "windows" {
			_ = exec.Command("certutil", "-user", "-delstore", "Root", "Snirect Root CA").Run()
		} else {
			_ = sysproxy.UninstallCert(certPath(appDir))
		}
	case "firefox":
		_ = sysproxy.UninstallFirefoxCert()
	case "chromium":
		// Chromium mode never touches the system certificate store.
	}

	// Remove local certs directory
	cd := certDir(appDir)
	_ = os.RemoveAll(cd)

	// Remove SPKI hash file if present
	_ = os.Remove(filepath.Join(appDir, "spki_hash.txt"))
	logger.Control().Info("all certificate residuals removed", "mode", mode)
}