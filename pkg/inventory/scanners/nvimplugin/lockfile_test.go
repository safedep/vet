package nvimplugin

import (
	"path/filepath"
	"testing"
)

func TestReadLockfile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lazy-lock.json")
	writeFile(t, path, `{
		"snacks.nvim": { "branch": "main", "commit": "`+testSHA+`" },
		"catppuccin":  { "branch": "main", "commit": "af58927cee9e63d4be0f337ba7c7c1af04a4870f" }
	}`)

	lock, err := readLockfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(lock) != 2 {
		t.Fatalf("len = %d, want 2", len(lock))
	}
	if lock["snacks.nvim"].Commit != testSHA {
		t.Errorf("snacks.nvim commit = %q", lock["snacks.nvim"].Commit)
	}
	if lock["catppuccin"].Branch != "main" {
		t.Errorf("catppuccin branch = %q", lock["catppuccin"].Branch)
	}
}

func TestReadLockfile_Absent(t *testing.T) {
	lock, err := readLockfile(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Errorf("absent lock file should not error, got %v", err)
	}
	if lock != nil {
		t.Errorf("expected nil map, got %v", lock)
	}
}

func TestReadLockfile_Malformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lazy-lock.json")
	writeFile(t, path, `{ "snacks.nvim": { "commit": `)

	lock, err := readLockfile(path)
	if err == nil {
		t.Error("malformed lock file should return an error")
	}
	if lock != nil {
		t.Errorf("expected nil map on error, got %v", lock)
	}
}
