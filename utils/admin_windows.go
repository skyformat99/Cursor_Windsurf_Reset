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

type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         syscall.Handle
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     syscall.Handle
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    syscall.Handle
	dwHotKey     uint32
	hIcon        syscall.Handle
	hProcess     syscall.Handle
}

func IsRunningAsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

func ElevateToAdmin() error {
	verb := "runas"
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	args := strings.Join(os.Args[1:], " ")
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %v", err)
	}

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var info shellExecuteInfo
	info.cbSize = uint32(unsafe.Sizeof(info))
	info.lpVerb = verbPtr
	info.lpFile = exePtr
	info.lpParameters = argPtr
	info.lpDirectory = cwdPtr
	info.nShow = syscall.SW_NORMAL

	modshell32 := syscall.NewLazyDLL("shell32.dll")
	procShellExecuteEx := modshell32.NewProc("ShellExecuteExW")
	ret, _, err := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		return fmt.Errorf("failed to elevate: %v", err)
	}

	os.Exit(0)
	return nil
}
