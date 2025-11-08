//go:build windows

package cleaner

import (
    "fmt"
    "os/exec"
    "regexp"
    "strings"
    "syscall"

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
            log.Error().Err(err).Str("path", regConfig.Path).Msg("Failed to parse registry path")
            failedKeys++
            continue
        }

        if len(regConfig.WildcardSubKeys) > 0 {
            for _, pattern := range regConfig.WildcardSubKeys {
                matches, err := findMatchingRegistryKeys(rootKey, subKeyPath, pattern)
                if err != nil {
                    log.Error().Err(err).
                        Str("path", regConfig.Path).
                        Str("pattern", pattern).
                        Msg("Failed to find matching registry keys")
                    failedKeys++
                    continue
                }

                for _, match := range matches {
                    totalKeys++
                    fullPath := subKeyPath + "\\" + match
                    if err := registry.DeleteKey(rootKey, fullPath); err != nil {
                        if err != registry.ErrNotExist {
                            log.Error().Err(err).
                                Str("path", fullPath).
                                Msg("Failed to delete matching registry key")
                            failedKeys++
                        }
                    } else {
                        deletedPaths++
                        cleanedKeys++
                        log.Info().
                            Str("path", fullPath).
                            Str("pattern", pattern).
                            Msg("Successfully deleted matching registry key")
                    }
                }
            }
            continue
        }

        // 打开注册表键
        key, err := registry.OpenKey(rootKey, subKeyPath, registry.ALL_ACCESS)
        if err != nil {
            if err != registry.ErrNotExist {
                log.Error().Err(err).Str("path", regConfig.Path).Msg("Failed to open registry key")
                failedKeys++
            }
            continue
        }

        if regConfig.FullClean {
            // 完全删除该键
            err = registry.DeleteKey(rootKey, subKeyPath)
            if err != nil {
                log.Error().Err(err).Str("path", regConfig.Path).Msg("Failed to delete registry key")
                failedKeys++
            } else {
                deletedPaths++
                totalKeys++
                cleanedKeys++
                log.Info().Str("path", regConfig.Path).Msg("Successfully deleted registry key")
            }
            key.Close()
            continue
        }

        for _, valueName := range regConfig.Keys {
            totalKeys++
            err = key.DeleteValue(valueName)
            if err != nil {
                if err != registry.ErrNotExist {
                    log.Error().Err(err).
                        Str("path", regConfig.Path).
                        Str("value", valueName).
                        Msg("Failed to delete registry value")
                    failedKeys++
                }
            } else {
                cleanedKeys++
                log.Info().
                    Str("path", regConfig.Path).
                    Str("value", valueName).
                    Msg("Successfully deleted registry value")
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
    cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s", processName))
    cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

    output, err := cmd.Output()
    if err != nil {
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
