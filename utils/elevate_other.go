//go:build !windows
// +build !windows

package utils

// IsRunAsAdmin 在非 Windows 平台上总是返回 true
func IsRunAsAdmin() bool {
	return true
}

// RunMeElevated 在非 Windows 平台上是空操作
func RunMeElevated() error {
	return nil
}
