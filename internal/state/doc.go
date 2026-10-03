// Package state keeps vet's local scan state on dry/localdb: the scan index
// vet.db, one scan file for each scan under scans/, and the enrichment cache
// cache.db in the cache directory. The scan file implements plugin.State and
// plugin.Report, and the report renders from it.
package state
