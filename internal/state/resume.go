package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// DefaultContinueWithin is the continue window of the scan state design,
// section 4.1.
const DefaultContinueWithin = 24 * time.Hour

// OptionsHash hashes the scan options that change what vet reads, extracts
// or enriches. The caller passes a struct, so encoding/json gives one byte
// form for each value.
func OptionsHash(opts any) (string, error) {
	b, err := json.Marshal(opts)
	if err != nil {
		return "", fmt.Errorf("hash scan options: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Reason tells why vet does not continue a stopped scan.
type Reason string

const (
	ReasonNone           Reason = ""
	ReasonFresh          Reason = "fresh"
	ReasonOptionsChanged Reason = "options-changed"
	ReasonVersionChanged Reason = "version-changed"
	ReasonTooOld         Reason = "too-old"
	ReasonLive           Reason = "live"
)

// ContinueRequest holds the inputs of the continue rules.
type ContinueRequest struct {
	TargetKey   string
	OptionsHash string
	VetVersion  string
	// Within is the continue window. Zero means DefaultContinueWithin.
	Within time.Duration
	// Resume removes the age limit.
	Resume bool
	// Fresh always starts a new scan.
	Fresh bool
	Now   time.Time
}

// ContinueDecision is the result of the continue rules. Continue is the
// scan to continue, or nil for a new scan. When a stopped scan exists that
// vet does not continue, Stopped names it and Reason says why.
type ContinueDecision struct {
	Continue *IndexEntry
	Stopped  *IndexEntry
	Reason   Reason
}

// DecideContinue applies the rules of the scan state design, section 4.1,
// to the last stopped scan of the target. It first marks each running scan
// of the target that no process holds as interrupted.
func (s *Store) DecideContinue(ctx context.Context, r ContinueRequest) (*ContinueDecision, error) {
	entries, err := s.index.List(ctx, ListOptions{
		TargetKey: r.TargetKey,
		Statuses:  []Status{StatusRunning, StatusInterrupted},
	})
	if err != nil {
		return nil, err
	}
	var live, stopped *IndexEntry
	for _, e := range entries {
		if e.Status == StatusRunning {
			running, err := isLive(e.File)
			if err != nil {
				return nil, err
			}
			if running {
				live = first(live, e)
				continue
			}
			if err := s.markInterrupted(ctx, e); err != nil {
				return nil, err
			}
		}
		stopped = first(stopped, e)
	}

	d := &ContinueDecision{Stopped: stopped}
	switch {
	case stopped == nil:
		if live != nil {
			d.Stopped, d.Reason = live, ReasonLive
		}
	case r.Fresh:
		d.Reason = ReasonFresh
	case stopped.OptionsHash != r.OptionsHash:
		d.Reason = ReasonOptionsChanged
	case stopped.VetVersion != r.VetVersion:
		d.Reason = ReasonVersionChanged
	case !r.Resume && r.now().Sub(stopped.UpdatedAt) > r.within():
		d.Reason = ReasonTooOld
	default:
		d.Continue, d.Stopped = stopped, nil
	}
	return d, nil
}

func (r ContinueRequest) now() time.Time {
	if r.Now.IsZero() {
		return time.Now()
	}
	return r.Now
}

func (r ContinueRequest) within() time.Duration {
	if r.Within <= 0 {
		return DefaultContinueWithin
	}
	return r.Within
}

// first keeps the newest entry. List returns the newest scan first.
func first(cur, e *IndexEntry) *IndexEntry {
	if cur != nil {
		return cur
	}
	return e
}

func (s *Store) markInterrupted(ctx context.Context, e *IndexEntry) error {
	e.Status = StatusInterrupted
	return s.index.Update(ctx, e)
}

// ContinueScan locks and opens a stopped scan, and marks it running again.
func (s *Store) ContinueScan(ctx context.Context, e *IndexEntry, pid int, host string) (*Scan, error) {
	if _, err := os.Stat(e.File); err != nil {
		return nil, fmt.Errorf("scan %s: the scan file %s is missing: %w", e.ID, e.File, err)
	}
	lock, err := acquireLock(e.File)
	if err != nil {
		return nil, err
	}
	scan, err := s.OpenScan(ctx, e)
	if err != nil {
		return nil, errors.Join(err, lock.release())
	}
	scan.lock = lock
	e.Status, e.Continued, e.PID, e.Host = StatusRunning, true, pid, host
	e.UpdatedAt = time.Now().UTC()
	if err := s.index.Update(ctx, e); err != nil {
		return nil, errors.Join(err, scan.Close())
	}
	return scan, nil
}
