// Package plugintest holds conformance checks for vet plugins, as
// testing/fstest holds them for file systems. A plugin author runs them in
// the plugin's own tests, with an in-memory State and Report and no SQLite.
package plugintest
