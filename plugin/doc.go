// Package plugin holds the interfaces that vet plugins implement and the
// registry that names them. Each interface has one method. The registry,
// not the interface, holds the name. A first-party plugin registers in
// cmd/vet. A community plugin in another module registers from its own init,
// as a database/sql driver does.
package plugin
