package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const (
	maxLogFileSize = 10 * 1024 * 1024 // 10MB
	maxLogFiles    = 5                // 保留最近5个日志文件
)

var (
	globalLogger *Logger
	once         sync.Once
)

// Logger 增强的日志系统
type Logger struct {
	log          zerolog.Logger
	logFile      *os.File
	logDir       string
	currentSize  int64
	mu           sync.Mutex
	rotateOnSize bool
}

// Init 初始化全局日志系统
func Init(logDir string, verbose bool) (*Logger, error) {
	var err error
	once.Do(func() {
		globalLogger, err = NewLogger(logDir, verbose)
	})
	return globalLogger, err
}

// GetGlobalLogger 获取全局日志实例
func GetGlobalLogger() *Logger {
	return globalLogger
}

// NewLogger 创建新的日志实例
func NewLogger(logDir string, verbose bool) (*Logger, error) {
	// 创建日志目录
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	logger := &Logger{
		logDir:       logDir,
		rotateOnSize: true,
	}

	// 创建日志文件
	if err := logger.openLogFile(); err != nil {
		return nil, err
	}

	// 设置日志级别
	logLevel := zerolog.InfoLevel
	if verbose {
		logLevel = zerolog.DebugLevel
	}

	// 创建多输出写入器（控制台 + 文件）
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		NoColor:    false,
		TimeFormat: "15:04:05",
	}

	multiWriter := zerolog.MultiLevelWriter(consoleWriter, logger.logFile)
	logger.log = zerolog.New(multiWriter).
		Level(logLevel).
		With().
		Timestamp().
		Caller().
		Logger()

	logger.Info("日志系统初始化成功",
		"log_dir", logDir,
		"log_file", logger.getCurrentLogPath(),
		"verbose", verbose)

	// 记录系统信息
	logger.logSystemInfo()

	return logger, nil
}

// openLogFile 打开日志文件
func (l *Logger) openLogFile() error {
	logPath := l.getCurrentLogPath()

	// 检查现有文件大小
	if fileInfo, err := os.Stat(logPath); err == nil {
		if fileInfo.Size() >= maxLogFileSize {
			// 轮转日志文件
			if err := l.rotateLogFiles(); err != nil {
				return err
			}
		}
	}

	// 打开或创建日志文件
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	l.logFile = file
	l.currentSize = 0

	// 获取当前文件大小
	if fileInfo, err := file.Stat(); err == nil {
		l.currentSize = fileInfo.Size()
	}

	return nil
}

// getCurrentLogPath 获取当前日志文件路径
func (l *Logger) getCurrentLogPath() string {
	timestamp := time.Now().Format("2006-01-02")
	return filepath.Join(l.logDir, fmt.Sprintf("cleanup_%s.log", timestamp))
}

// rotateLogFiles 轮转日志文件
func (l *Logger) rotateLogFiles() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// 关闭当前日志文件
	if l.logFile != nil {
		l.logFile.Close()
	}

	// 重命名当前日志文件
	currentPath := l.getCurrentLogPath()
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	archivePath := filepath.Join(l.logDir, fmt.Sprintf("cleanup_%s.log", timestamp))

	if err := os.Rename(currentPath, archivePath); err != nil {
		// 如果重命名失败，可能文件不存在，继续
	}

	// 清理旧日志文件
	l.cleanOldLogFiles()

	// 打开新的日志文件
	return l.openLogFile()
}

// cleanOldLogFiles 清理旧的日志文件
func (l *Logger) cleanOldLogFiles() {
	entries, err := os.ReadDir(l.logDir)
	if err != nil {
		return
	}

	// 收集日志文件并排序
	var logFiles []os.DirEntry
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "cleanup_") && strings.HasSuffix(entry.Name(), ".log") {
			logFiles = append(logFiles, entry)
		}
	}

	// 如果超过最大文件数，删除最旧的
	if len(logFiles) > maxLogFiles {
		// 按修改时间排序（最旧的在前）
		for i := 0; i < len(logFiles)-maxLogFiles; i++ {
			filePath := filepath.Join(l.logDir, logFiles[i].Name())
			os.Remove(filePath)
		}
	}
}

// logSystemInfo 记录系统信息
func (l *Logger) logSystemInfo() {
	l.Info("系统信息",
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
		"go_version", runtime.Version(),
		"num_cpu", runtime.NumCPU(),
		"num_goroutine", runtime.NumGoroutine())
}

// RecoverPanic 记录panic并恢复
func (l *Logger) RecoverPanic(context string) {
	if r := recover(); r != nil {
		stack := debug.Stack()
		l.Error("程序发生panic",
			"context", context,
			"panic", r,
			"stack_trace", string(stack))

		// 写入单独的崩溃报告文件
		l.writeCrashReport(context, r, stack)

		// 重新panic以便调用者处理
		panic(r)
	}
}

// writeCrashReport 写入崩溃报告
func (l *Logger) writeCrashReport(context string, panicValue interface{}, stack []byte) {
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	crashFile := filepath.Join(l.logDir, fmt.Sprintf("crash_report_%s.txt", timestamp))

	file, err := os.Create(crashFile)
	if err != nil {
		l.Error("无法创建崩溃报告文件", "error", err)
		return
	}
	defer file.Close()

	fmt.Fprintf(file, "=== 崩溃报告 ===\n")
	fmt.Fprintf(file, "时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "上下文: %s\n", context)
	fmt.Fprintf(file, "Panic: %v\n\n", panicValue)
	fmt.Fprintf(file, "调用栈:\n%s\n", string(stack))
	fmt.Fprintf(file, "\n系统信息:\n")
	fmt.Fprintf(file, "OS: %s\n", runtime.GOOS)
	fmt.Fprintf(file, "ARCH: %s\n", runtime.GOARCH)
	fmt.Fprintf(file, "Go Version: %s\n", runtime.Version())
	fmt.Fprintf(file, "CPUs: %d\n", runtime.NumCPU())
	fmt.Fprintf(file, "Goroutines: %d\n", runtime.NumGoroutine())

	l.Info("崩溃报告已保存", "file", crashFile)
}

// LogOperation 记录操作开始和结束
func (l *Logger) LogOperation(operation string, fn func() error) error {
	l.Info("操作开始", "operation", operation)
	start := time.Now()

	err := fn()

	duration := time.Since(start)
	if err != nil {
		l.Error("操作失败",
			"operation", operation,
			"duration", duration,
			"error", err)
	} else {
		l.Info("操作完成",
			"operation", operation,
			"duration", duration)
	}

	return err
}

// checkRotation 检查是否需要轮转日志
func (l *Logger) checkRotation(size int) {
	if !l.rotateOnSize {
		return
	}

	l.currentSize += int64(size)
	if l.currentSize >= maxLogFileSize {
		if err := l.rotateLogFiles(); err != nil {
			// 轮转失败，继续使用当前文件
			fmt.Fprintf(os.Stderr, "Failed to rotate log files: %v\n", err)
		}
	}
}

// Close 关闭日志系统
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.Info("关闭日志系统")

	if l.logFile != nil {
		if err := l.logFile.Sync(); err != nil {
			return err
		}
		return l.logFile.Close()
	}

	return nil
}

// Debug 记录调试级别日志
func (l *Logger) Debug(msg string, keysAndValues ...interface{}) {
	event := l.log.Debug()
	l.addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Info 记录信息级别日志
func (l *Logger) Info(msg string, keysAndValues ...interface{}) {
	event := l.log.Info()
	l.addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Warn 记录警告级别日志
func (l *Logger) Warn(msg string, keysAndValues ...interface{}) {
	event := l.log.Warn()
	l.addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Error 记录错误级别日志
func (l *Logger) Error(msg string, keysAndValues ...interface{}) {
	// 添加调用栈信息
	pc, file, line, ok := runtime.Caller(1)
	if ok {
		funcName := runtime.FuncForPC(pc).Name()
		keysAndValues = append(keysAndValues, "caller_file", file, "caller_line", line, "caller_func", funcName)
	}

	event := l.log.Error()
	l.addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Fatal 记录致命错误并退出
func (l *Logger) Fatal(msg string, keysAndValues ...interface{}) {
	event := l.log.Fatal()
	l.addFields(event, keysAndValues...)
	event.Msg(msg)
}

// addFields 添加键值对字段
func (l *Logger) addFields(event *zerolog.Event, keysAndValues ...interface{}) {
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 >= len(keysAndValues) {
			break
		}

		key, ok := keysAndValues[i].(string)
		if !ok {
			continue
		}

		value := keysAndValues[i+1]
		switch v := value.(type) {
		case string:
			event.Str(key, v)
		case int:
			event.Int(key, v)
		case int64:
			event.Int64(key, v)
		case float64:
			event.Float64(key, v)
		case bool:
			event.Bool(key, v)
		case error:
			event.Err(v)
		case time.Duration:
			event.Dur(key, v)
		default:
			event.Interface(key, v)
		}
	}
}

// GetWriter 获取日志写入器
func (l *Logger) GetWriter() io.Writer {
	return l.logFile
}

// Sync 同步日志到文件
func (l *Logger) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.logFile != nil {
		return l.logFile.Sync()
	}
	return nil
}
