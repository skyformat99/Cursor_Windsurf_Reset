// +build !windows

package utils

func IsRunningAsAdmin() bool {
    return true
}

func ElevateToAdmin() error {
    return nil
}
