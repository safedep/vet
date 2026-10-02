package model

import "fmt"

// Change marks how pull request mode or endpoint mode saw a package or a
// file change against the base. It is empty in a full scan (decisions P4).
type Change string

const (
	ChangeNone       Change = ""
	ChangeAdded      Change = "ADDED"
	ChangeUpgraded   Change = "UPGRADED"
	ChangeDowngraded Change = "DOWNGRADED"
	ChangeModified   Change = "MODIFIED"
	ChangeRemoved    Change = "REMOVED"
	ChangeUnchanged  Change = "UNCHANGED"
)

// Valid reports whether the change is in the closed set.
func (c Change) Valid() bool {
	switch c {
	case ChangeNone, ChangeAdded, ChangeUpgraded, ChangeDowngraded, ChangeModified, ChangeRemoved, ChangeUnchanged:
		return true
	}
	return false
}

// Introduces reports whether the change brings new content into the target.
// Pull request mode reports findings only for these changes.
func (c Change) Introduces() bool {
	switch c {
	case ChangeAdded, ChangeUpgraded, ChangeDowngraded, ChangeModified:
		return true
	}
	return false
}

// ParseChange parses a change name.
func ParseChange(s string) (Change, error) {
	c := Change(s)
	if !c.Valid() {
		return "", fmt.Errorf("unknown change %q", s)
	}
	return c, nil
}
