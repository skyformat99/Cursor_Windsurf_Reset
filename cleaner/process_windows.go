//go:build windows

package cleaner

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

func (e *Engine) cleanRegistry(appName string) error {
	app, exists := e.config.Applications[appName]
	if !exists {
		return fmt.Errorf("application %s not found in config", appName)
	}

	if len(app.RegKeys) == 0 {
		return nil
	}

	e.sendProgress(ProgressUpdate{
		Type:     "registry",
		Message:  e.localizeMessage("StartingRegistryCleaning", nil),
		AppName:  appName,
		Phase:    "registry",
		Progress: 70,
	})

	var (
		totalKeys    int
		cleanedKeys  int
		failedKeys   int
		deletedPaths int
	)

	for _, regConfig := range app.RegKeys {
		rootKey, subKeyPath, err := parseRegistryPath(regConfig.Path)
		if err != nil {
			logError("Failed to parse registry path", "path", regConfig.Path, "error", err)
			failedKeys++
			continue
		}

		if len(regConfig.WildcardSubKeys) > 0 {
			for _, pattern := range regConfig.WildcardSubKeys {
					matches, err := findMatchingRegistryKeys(rootKey, subKeyPath, pattern)
					if err != nil {
						logError("Failed to find matching registry keys",
							"path", regConfig.Path,
							"pattern", pattern,
							"error", err)
						failedKeys++
						continue
					}

					for _, match := range matches {
					totalKeys++
					fullPath := subKeyPath + "\\" + match
						if err := registry.DeleteKey(rootKey, fullPath); err != nil {
							if err != registry.ErrNotExist {
								logError("Failed to delete matching registry key",
									"path", fullPath,
									"pattern", pattern,
									"error", err)
								failedKeys++
							}
						} else {
							deletedPaths++
							cleanedKeys++
							logInfo("Successfully deleted matching registry key",
								"path", fullPath,
								"pattern", pattern)
						}
					}
				}
				continue
			}

		// 打开注册表键
			key, err := registry.OpenKey(rootKey, subKeyPath, registry.ALL_ACCESS)
			if err != nil {
				if err != registry.ErrNotExist {
					logError("Failed to open registry key", "path", regConfig.Path, "error", err)
					failedKeys++
				}
				continue
			}

			if regConfig.FullClean {
				err = registry.DeleteKey(rootKey, subKeyPath)
				if err != nil {
					logError("Failed to delete registry key", "path", regConfig.Path, "error", err)
					failedKeys++
				} else {
					deletedPaths++
					totalKeys++
					cleanedKeys++
					logInfo("Successfully deleted registry key", "path", regConfig.Path)
				}
				key.Close()
				continue
			}

			for _, valueName := range regConfig.Keys {
				totalKeys++
				err = key.DeleteValue(valueName)
				if err != nil {
					if err != registry.ErrNotExist {
						logError("Failed to delete registry value",
							"path", regConfig.Path,
							"value", valueName,
							"error", err)
						failedKeys++
					}
				} else {
					cleanedKeys++
					logInfo("Successfully deleted registry value",
						"path", regConfig.Path,
						"value", valueName)
				}
			}

		key.Close()
	}

	e.sendProgress(ProgressUpdate{
		Type: "registry",
		Message: e.localizeMessage("RegistryCleaningComplete", map[string]interface{}{
			"Cleaned": cleanedKeys,
			"Total":   totalKeys,
			"Failed":  failedKeys,
			"Deleted": deletedPaths,
		}),
		AppName:  appName,
		Phase:    "registry",
		Progress: 75,
	})

	return nil
}

func parseRegistryPath(path string) (registry.Key, string, error) {
	parts := strings.SplitN(path, "\\", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("invalid registry path format: %s", path)
	}

	var rootKey registry.Key
	switch strings.ToUpper(parts[0]) {
	case "HKEY_CLASSES_ROOT", "HKCR":
		rootKey = registry.CLASSES_ROOT
	case "HKEY_CURRENT_USER", "HKCU":
		rootKey = registry.CURRENT_USER
	case "HKEY_LOCAL_MACHINE", "HKLM":
		rootKey = registry.LOCAL_MACHINE
	case "HKEY_USERS", "HKU":
		rootKey = registry.USERS
	case "HKEY_CURRENT_CONFIG", "HKCC":
		rootKey = registry.CURRENT_CONFIG
	default:
		return 0, "", fmt.Errorf("unknown registry root key: %s", parts[0])
	}

	return rootKey, parts[1], nil
}

func (e *Engine) isProcessRunning(processName string) bool {
	// 创建带超时的上下文，防止无限等待
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s", processName))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.Output()
	if err != nil {
		// 超时或其他错误
		if ctx.Err() == context.DeadlineExceeded {
			logWarn("Process check timed out, assuming process is not running", "process", processName)
			return false
		}
		logDebug("Failed to check process, assuming process is not running",
			"process", processName,
			"error", err)
		return false
	}

	return strings.Contains(strings.ToLower(string(output)), strings.ToLower(processName))
}

func findMatchingRegistryKeys(rootKey registry.Key, basePath, pattern string) ([]string, error) {
	var matches []string

	key, err := registry.OpenKey(rootKey, basePath, registry.READ)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to open base path %s: %w", basePath, err)
	}
	defer key.Close()

	keyInfo, err := key.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get key info for %s: %w", basePath, err)
	}

	subKeys, err := key.ReadSubKeyNames(int(keyInfo.SubKeyCount))
	if err != nil {
		return nil, fmt.Errorf("failed to read subkeys from %s: %w", basePath, err)
	}

	pattern = strings.ReplaceAll(pattern, "*", ".*")
	pattern = "^" + pattern + "$"
	matcher, err := regexp.Compile(strings.ToLower(pattern))
	if err != nil {
		return nil, fmt.Errorf("invalid pattern %s: %w", pattern, err)
	}

	for _, subKey := range subKeys {
		if matcher.MatchString(strings.ToLower(subKey)) {
			matches = append(matches, subKey)
		}
	}

	return matches, nil
}
