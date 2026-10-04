//go:build !windows

package endpoint

import "os"

func privileged() bool { return os.Geteuid() == 0 }
