package inventory

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/safedep/vet/v2/report"
)

// WALFile is the name of the write-ahead log in the state directory
// (decisions P11).
const WALFile = "inventory-sync.wal"

// maxBatches bounds the log. The oldest batch goes first.
const maxBatches = 50

// Batch is the inventory of one audit that waits to be sent.
type Batch struct {
	At       time.Time              `json:"at"`
	Endpoint string                 `json:"endpoint"`
	Items    []report.InventoryItem `json:"items"`
}

// WAL keeps the batches that SafeDep Cloud has not received, one JSON line
// for each batch, in a file with mode 0600.
type WAL struct{ path string }

// NewWAL returns the log of a state directory.
func NewWAL(stateDir string) *WAL { return &WAL{path: filepath.Join(stateDir, WALFile)} }

// Path returns the file of the log.
func (w *WAL) Path() string { return w.path }

// Batches returns the batches of the log, oldest first.
func (w *WAL) Batches() ([]Batch, error) {
	b, err := os.ReadFile(w.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Batch
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 64<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var batch Batch
		if err := json.Unmarshal(sc.Bytes(), &batch); err != nil {
			return nil, fmt.Errorf("inventory log %s: %w", w.path, err)
		}
		out = append(out, batch)
	}
	return out, sc.Err()
}

// Append adds a batch, and drops the oldest batches over the limit.
func (w *WAL) Append(b Batch) error {
	batches, err := w.Batches()
	if err != nil {
		return err
	}
	batches = append(batches, b)
	if len(batches) > maxBatches {
		batches = batches[len(batches)-maxBatches:]
	}
	return w.write(batches)
}

// Clear removes every batch.
func (w *WAL) Clear() error {
	if err := os.Remove(w.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (w *WAL) write(batches []Batch) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for i := range batches {
		if err := enc.Encode(&batches[i]); err != nil {
			return err
		}
	}
	tmp := w.path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, w.path)
}
