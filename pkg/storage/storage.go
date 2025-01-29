package storage

// Storage interface defines a generic contract for implementing
// a storage driver in the system. This usually means wrapping
// a DB client with our defined interface.
type Storage[T any] interface {
	// Returns a client to the underlying storage driver.
	// We will NOT hide the underlying storage driver because for an ORM
	// which already abstracts DB connection, its unnecessary work to abstract
	// an ORM and then implement function wrappers for all ORM operations.
	Client() (T, error)

	// Close any open connections, file descriptors and free
	// any resources used by the storage driver
	Close() error
}
