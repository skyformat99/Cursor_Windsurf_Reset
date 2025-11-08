//go:build windows
// +build windows

package utils

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	CREATE_NEW_CONSOLE    = 0x00000010
	NORMAL_PRIORITY_CLASS = 0x00000020
)

var (
	shell32            = windows.NewLazySystemDLL("shell32.dll")
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	IsUserAnAdmin      = shell32.NewProc("IsUserAnAdmin")
	ShellExecuteW      = shell32.NewProc("ShellExecuteW")
	GetModuleFileNameW = kernel32.NewProc("GetModuleFileNameW")
)

// IsRunAsAdmin 检查当前程序是否以管理员权限运行
func IsRunAsAdmin() bool {
	is, _, _ := IsUserAnAdmin.Call()
	return is != 0
}

// RunMeElevated 以管理员权限重新启动程序
func RunMeElevated() error {
	// 获取当前可执行文件路径
	exePath, err := GetCurrentExePath()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// 获取命令行参数
	args := strings.Join(os.Args[1:], " ")

	// 准备 ShellExecute 参数
	verb := syscall.StringToUTF16Ptr("runas")
	exec := syscall.StringToUTF16Ptr(exePath)
	params := syscall.StringToUTF16Ptr(args)
	dir := syscall.StringToUTF16Ptr("")
	show := uintptr(1) // SW_NORMAL

	// 使用 ShellExecute 以管理员权限启动新进程
	ret, _, _ := ShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(exec)),
		uintptr(unsafe.Pointer(params)),
		uintptr(unsafe.Pointer(dir)),
		show,
	)

	if ret <= 32 { // ShellExecute returns error if result <= 32
		return fmt.Errorf("failed to elevate process, ShellExecute returned %d", ret)
	}

	// 退出当前进程
	os.Exit(0)
	return nil
}

// GetCurrentExePath 获取当前可执行文件的完整路径
func GetCurrentExePath() (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	h, err := windows.GetCurrentProcess()
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	n, _, _ := GetModuleFileNameW.Call(0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return "", fmt.Errorf("GetModuleFileNameW failed")
	}

	return syscall.UTF16ToString(buf), nil
}
