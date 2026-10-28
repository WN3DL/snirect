package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// FindChromiumPath resolves the Chromium/Chrome/Edge executable.
func FindChromiumPath(customPath string) (string, error) {
	if customPath != "" {
		if _, err := os.Stat(customPath); err == nil {
			return customPath, nil
		}
		return "", fmt.Errorf("specified chromium path not found: %s", customPath)
	}

	if runtime.GOOS != "windows" {
		candidates := []string{"google-chrome", "chromium", "chromium-browser", "microsoft-edge"}
		for _, name := range candidates {
			if path, err := exec.LookPath(name); err == nil {
				return path, nil
			}
		}
		return "", errors.New("chromium executable not found on PATH. Please specify via --chromium-path or config.toml")
	}

	programFiles := os.Getenv("ProgramFiles")
	programFilesX86 := os.Getenv("ProgramFiles(x86)")
	localAppData := os.Getenv("LocalAppData")

	candidates := []string{
		filepath.Join(programFiles, "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(programFilesX86, "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(localAppData, "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(programFilesX86, "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(programFiles, "Microsoft", "Edge", "Application", "msedge.exe"),
	}

	for _, p := range candidates {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}
	return "", errors.New("chrome/edge executable not found in standard locations. Please specify via --chromium-path or config.toml")
}

// FindFirefoxPath resolves the Firefox executable.
func FindFirefoxPath(customPath string) (string, error) {
	if customPath != "" {
		if _, err := os.Stat(customPath); err == nil {
			return customPath, nil
		}
		return "", fmt.Errorf("specified firefox path not found: %s", customPath)
	}

	if runtime.GOOS != "windows" {
		if path, err := exec.LookPath("firefox"); err == nil {
			return path, nil
		}
		return "", errors.New("firefox executable not found on PATH. Please specify via --firefox-path or config.toml")
	}

	programFiles := os.Getenv("ProgramFiles")
	programFilesX86 := os.Getenv("ProgramFiles(x86)")

	candidates := []string{
		filepath.Join(programFiles, "Mozilla Firefox", "firefox.exe"),
		filepath.Join(programFilesX86, "Mozilla Firefox", "firefox.exe"),
	}

	for _, p := range candidates {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}
	return "", errors.New("firefox executable not found in standard locations. Please specify via --firefox-path or config.toml")
}

// LaunchChromium launches an isolated sandboxed Chromium instance.
func LaunchChromium(binPath string, port int, spkiHash string, appDir string) (*exec.Cmd, error) {
	browserData := filepath.Join(appDir, "BrowserData")
	args := []string{
		fmt.Sprintf("--proxy-server=http://127.0.0.1:%d", port),
		fmt.Sprintf("--ignore-certificate-errors-spki-list=%s", spkiHash),
		fmt.Sprintf("--user-data-dir=%s", browserData),
		"--disable-quic",
	}

	cmd := exec.Command(binPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start chromium browser: %w", err)
	}
	return cmd, nil
}

// LaunchFirefox launches the Firefox browser.
func LaunchFirefox(binPath string) (*exec.Cmd, error) {
	cmd := exec.Command(binPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start firefox: %w", err)
	}
	return cmd, nil
}
