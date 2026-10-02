// Package config holds vet's typed configuration: the Config struct, its
// defaults, its layers and its validation. It is the only package that reads
// environment variables for configuration. A command gets a *Config from the
// root command and never reads a package global.
package config
