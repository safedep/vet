//go:build windows

package endpoint

import "golang.org/x/sys/windows"

// privileged reports an elevated process: an administrator can read the
// profile of every user.
func privileged() bool { return windows.GetCurrentProcessToken().IsElevated() }
