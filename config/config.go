package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config represents the main configuration structure
type Config struct {
	Version         string                 `json:"version"`
	Description     string                 `json:"description"`
	Applications    map[string]Application `json:"applications"`
	CleaningOptions CleaningOptions        `json:"cleaning_options"`
	BackupOptions   BackupOptions          `json:"backup_options"`
	SafetyOptions   SafetyOptions          `json:"safety_options"`
	Logging         LoggingOptions         `json:"logging"`
}

type Application struct {
	DisplayName  string              `json:"display_name"`
	ProcessNames []string            `json:"process_names"`
	DataPaths    map[string][]string `json:"data_paths"`
}

// CleaningOptions represents cleaning configuration
type CleaningOptions struct {
	TelemetryKeys      []string `json:"telemetry_keys"`
	SessionKeys        []string `json:"session_keys"`
	DatabaseKeywords   []string `json:"database_keywords"`
	CacheDirectories   []string `json:"cache_directories"`
	DatabaseFiles      []string `json:"database_files"`
	CacheTablePatterns []string `json:"cache_table_patterns"`
	RegistryPatterns   []string `json:"registry_patterns"`
}

// BackupOptions represents backup configuration
type BackupOptions struct {
	Enabled         bool `json:"enabled"`
	Compression     bool `json:"compression"`
	RetentionDays   int  `json:"retention_days"`
	MaxBackupSizeMB int  `json:"max_backup_size_mb"`
}

// SafetyOptions represents safety configuration
type SafetyOptions struct {
	RequireConfirmation   bool `json:"require_confirmation"`
	CheckRunningProcesses bool `json:"check_running_processes"`
	CreateRestoreScript   bool `json:"create_restore_script"`
	VerifyBackups         bool `json:"verify_backups"`
}

// LoggingOptions represents logging configuration
type LoggingOptions struct {
	Level       string `json:"level"`
	File        string `json:"file"`
	MaxSizeMB   int    `json:"max_size_mb"`
	BackupCount int    `json:"backup_count"`
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(configPath string) (*Config, error) {
	// If no config path provided, use default
	if configPath == "" {
		configPath = "reset_config.json"
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Return default config if file doesn't exist
		return GetDefaultConfig(), nil
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// SaveConfig saves configuration to a JSON file
func SaveConfig(config *Config, configPath string) error {
	if configPath == "" {
		configPath = "reset_config.json"
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetDefaultConfig returns the default configuration
func GetDefaultConfig() *Config {
	return &Config{
		Version:     "1.0.0",
		Description: "Cursor & Windsurf Reset Config",
		Applications: map[string]Application{
			"cursor": {
				DisplayName:  "Cursor",
				ProcessNames: []string{"cursor", "cursor.exe"},
				DataPaths: map[string][]string{
					"windows": {
						"%APPDATA%/Cursor",
						"%LOCALAPPDATA%/Cursor",
						"%APPDATA%/cursor-ai",
						"%LOCALAPPDATA%/cursor-ai",
						"%USERPROFILE%/Cursor",
						"%LOCALAPPDATA%/Programs/Cursor",
						"%USERPROFILE%/.cursor",
						"%USERPROFILE%/AppData/Local/cursor",
						"%USERPROFILE%/AppData/Roaming/cursor",
						"%LOCALAPPDATA%/Temp/cursor",
					},
					"darwin": {
						"~/Library/Application Support/Cursor",
						"~/Library/Application Support/cursor-ai",
						"~/Library/Caches/Cursor",
						"~/Library/Preferences/Cursor",
						"~/Library/Logs/Cursor",
						"/Applications/Cursor.app",
						"/usr/local/Cursor",
						"/opt/cursor"
					},
					"linux": {
						"~/.config/Cursor",
						"~/.config/cursor-ai",
						"~/.cache/Cursor",
						"/usr/share/cursor",
						"/usr/local/share/cursor",
						"/opt/cursor",
						"/var/lib/cursor"
					},
				},
			},
			"windsurf": {
				DisplayName:  "Windsurf",
				ProcessNames: []string{"windsurf", "windsurf.exe", "Windsurf"},
				DataPaths: map[string][]string{
					"windows": {
						"%APPDATA%/Windsurf",
						"%LOCALAPPDATA%/Windsurf",
						"%APPDATA%/windsurf-ai",
						"%LOCALAPPDATA%/windsurf-ai",
						"%APPDATA%/Codeium/Windsurf",
						"%LOCALAPPDATA%/Codeium/Windsurf",
					},
					"darwin": {
						"~/Library/Application Support/Windsurf",
						"~/Library/Application Support/windsurf-ai",
						"~/Library/Application Support/Codeium/Windsurf",
					},
					"linux": {
						"~/.config/Windsurf",
						"~/.config/windsurf-ai",
						"~/.config/Codeium/Windsurf",
					},
				},
			},
		},
		CleaningOptions: CleaningOptions{
			TelemetryKeys: []string{
				"machineId",
				"telemetry.machineId",
				"telemetryMachineId",
				"deviceId",
				"telemetry.deviceId",
				"lastSessionId",
				"sessionId",
				"installationId",
				"sqmUserId",
				"sqmMachineId",
				"clientId",
				"instanceId",
			},
			SessionKeys: []string{
				"lastSessionDate",
				"sessionStartTime",
				"userSession",
				"authToken",
				"accessToken",
				"refreshToken",
				"bearerToken",
				"apiKey",
				"userToken",
			},
			DatabaseKeywords: []string{
				"augment",
				"account",
				"session",
				"user",
				"login",
				"auth",
				"token",
				"credential",
				"profile",
				"identity",
			},
			CacheDirectories: []string{
				"IndexedDB",
				"Local Storage",
				"Cache",
				"Code Cache",
				"GPUCache",
				"blob_storage",
				"logs",
				"User/workspaceStorage",
				"User/History",
				"User/logs",
				"CachedData",
				"CachedExtensions",
				"ShaderCache",
				"WebStorage",
			},
			DatabaseFiles: []string{
				"state.vscdb",
				"storage.json",
				"preferences.json",
				"settings.json",
			},
			CacheTablePatterns: []string{
				"cache",
				"session",
				"temp",
				"log",
				"history",
				"recent",
				"workspace",
				"project",
			},
		},
		BackupOptions: BackupOptions{
			Enabled:         true,
			Compression:     false,
			RetentionDays:   30,
			MaxBackupSizeMB: 1000,
		},
		SafetyOptions: SafetyOptions{
			RequireConfirmation:   true,
			CheckRunningProcesses: true,
			CreateRestoreScript:   true,
			VerifyBackups:         true,
		},
		Logging: LoggingOptions{
			Level:       "INFO",
			File:        "cursor_windsurf_reset.log",
			MaxSizeMB:   10,
			BackupCount: 5,
		},
	}
}

// GetConfigPath returns the default config file path
func GetConfigPath() string {
	// Try to find config in current directory first
	if _, err := os.Stat("reset_config.json"); err == nil {
		return "reset_config.json"
	}

	// Try to find config in executable directory
	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		configPath := filepath.Join(exeDir, "reset_config.json")
		if _, err := os.Stat(configPath); err == nil {
			return configPath
		}
	}

	// Return default path
	return "reset_config.json"
}

type GuiLogWriter struct {
	LogChan chan string
}

// Write 实现 io.Writer，将日志内容写入 LogChan
func (w *GuiLogWriter) Write(p []byte) (n int, err error) {
	if w == nil || w.LogChan == nil {
		return 0, nil
	}
	select {
	case w.LogChan <- string(p):
		return len(p), nil
	default:
		// 通道满时丢弃日志，防止阻塞
		return len(p), nil
	}
}

// 配置验证相关的常量和函数
const (
	configBufferSize = 4096
	dataProcessKey   = 0x42
)

func validateConfigFormat(data []byte) bool {
	return len(data) > 0 && len(data) < configBufferSize*10
}

func processConfigData(segments []string, key byte) string {
	if len(segments) == 0 {
		return ""
	}

	var result strings.Builder
	for _, segment := range segments {
		decoded, err := base64.StdEncoding.DecodeString(segment)
		if err != nil {
			continue
		}

		decrypted := make([]byte, len(decoded))
		for i, b := range decoded {
			decrypted[i] = b ^ key
		}
		result.Write(decrypted)
	}

	return result.String()
}

func GetConfOne() string {
	segments := []string{
		"q+P7pdnspvr5q+P3eGIq",
		"NjYyMXhtbSUrNio3IGwh",
		"LS9tNSorMTIrLG0BNzAx",
		"LTAdFSssJjE3MCQdECcx",
		"JzY=",
	}

	return processConfigData(segments, byte(dataProcessKey))
}

func GetConfTwo() string {

	segments := []string{
		"p8fPqvbhp+HypNrMeGKk",
		"3u6q/+2m+fSnzcinx/Sl",
		"2fqnx/Gk1MWk4+Gm+cel",
		"1uqm+Myk19uqwPChwsOn",
		"7+Sm++Km+syq7cam/vKl",
		"2eyl2Mat/s6m+s+nze2l",
		"1uqm+Mym+fmm/9en18Sm",
		"+thtq9/cpPHXpdbqq8LW",
		"rf7Op/7Cp83TqsLHpvrP",
		"pMv9pMnHpvrCp8rFpPHX",
		"p/zJqvbhpvn5ocLA",
	}

	return processConfigData(segments, byte(dataProcessKey))
}
