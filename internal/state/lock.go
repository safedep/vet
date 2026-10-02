package state

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrLocked means that a live vet process holds the scan.
var ErrLocked = errors.New("state: a running vet process holds the scan")

// scanLock is the OS advisory lock of a running scan. The OS releases it
// when the process exits, also after a crash, so a held lock means a live
// process. vet locks a file next to the scan file, and not the scan file,
// because SQLite owns the locks of its database file.
type scanLock struct {
	f *os.File
}

func lockPath(scanFile string) string {
	return strings.TrimSuffix(scanFile, ".db") + ".lock"
}

func acquireLock(scanFile string) (*scanLock, error) {
	f, err := os.OpenFile(lockPath(scanFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open scan lock: %w", err)
	}
	ok, err := tryLockFile(f)
	if err != nil || !ok {
		if cerr := f.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
		if err != nil {
			return nil, fmt.Errorf("lock scan: %w", err)
		}
		return nil, ErrLocked
	}
	return &scanLock{f: f}, nil
}

func (l *scanLock) release() error {
	if l == nil {
		return nil
	}
	return errors.Join(unlockFile(l.f), l.f.Close())
}

// isLive reports whether a process holds the lock of the scan file.
func isLive(scanFile string) (bool, error) {
	if _, err := os.Stat(lockPath(scanFile)); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	l, err := acquireLock(scanFile)
	if errors.Is(err, ErrLocked) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, l.release()
}
