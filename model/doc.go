// Package model holds vet's package model: package identity, manifests, the
// dependency graph and the change marker. It is part of the public plugin API.
// It imports no storage or extraction type. It uses dry/api/pb for the
// package identity rules and the SafeDep API ecosystem enum, and keeps both
// behind its own types.
package model
