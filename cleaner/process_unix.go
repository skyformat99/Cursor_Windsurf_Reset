// +build !windows

package cleaner

func (e *Engine) isProcessRunning(processName string) bool {
    return false
}

func (e *Engine) cleanRegistry(appName string) error {
    return nil
}
