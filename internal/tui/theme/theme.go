// Package theme passes through dry/tui/theme.
package theme

import "github.com/safedep/dry/tui/theme"

// Theme is the design language: the palette and the icons.
type Theme = theme.Theme

// Role names a colour role of the palette.
type Role = theme.Role

const (
	RoleInfo         = theme.RoleInfo
	RoleSuccess      = theme.RoleSuccess
	RoleWarning      = theme.RoleWarning
	RoleError        = theme.RoleError
	RoleMuted        = theme.RoleMuted
	RoleText         = theme.RoleText
	RoleHeading      = theme.RoleHeading
	RolePath         = theme.RolePath
	RoleDiffAdd      = theme.RoleDiffAdd
	RoleDiffRemove   = theme.RoleDiffRemove
	RoleCritical     = theme.RoleCritical
	RoleHigh         = theme.RoleHigh
	RoleMedium       = theme.RoleMedium
	RoleLow          = theme.RoleLow
	RoleBrandPrimary = theme.RoleBrandPrimary
	RoleBrandAccent  = theme.RoleBrandAccent
	RoleBgCritical   = theme.RoleBgCritical
	RoleBgHigh       = theme.RoleBgHigh
	RoleBgMedium     = theme.RoleBgMedium
	RoleBgLow        = theme.RoleBgLow
	RoleBgInfo       = theme.RoleBgInfo
	RoleBgSuccess    = theme.RoleBgSuccess
	RoleBadgeText    = theme.RoleBadgeText
)

// Default returns the active theme.
func Default() Theme { return theme.Default() }
