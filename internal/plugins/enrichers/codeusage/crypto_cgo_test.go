//go:build cgo

package codeusage

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCryptoSignatures runs the crypto signatures on one program for each
// language. Each program calls the APIs the way their documentation does.
// The matched algorithms must be exactly the expected ones.
func TestCryptoSignatures(t *testing.T) {
	cases := map[string][]string{
		"crypto.py": {
			"md5", "sha1", "sha256", "sha512", "sha3", "blake", "hmac", "scrypt", "aes", "chacha20", "des",
			"rc4", "rsa", "ecdsa", "ed25519", "ecdh", "pbkdf2", "hkdf", "bcrypt", "argon2", "random", "tls", "x509", "jwt",
		},
		"crypto.js": {
			"md5", "sha1", "sha256", "sha512", "sha3", "hmac", "aes", "3des", "rc4", "rsa", "ecdsa", "ed25519",
			"ecdh", "pbkdf2", "scrypt", "hkdf", "bcrypt", "random", "tls", "x509", "jwt",
		},
		"Crypto.java": {
			"md5", "sha1", "sha256", "sha512", "hmac", "aes", "3des", "des", "rsa", "ecdsa", "ed25519",
			"ecdh", "pbkdf2", "bcrypt", "random", "tls", "x509", "jwt",
		},
		"crypto.go": {
			"md5", "sha1", "sha256", "sha512", "sha3", "hmac", "aes", "3des", "des", "rc4", "chacha20", "rsa",
			"ecdsa", "ed25519", "ecdh", "pbkdf2", "bcrypt", "scrypt", "argon2", "hkdf", "random", "tls", "ssh", "x509", "jwt",
		},
		"Crypto.cs": {
			"md5", "sha1", "sha256", "sha512", "hmac", "aes", "3des", "rsa", "ecdsa", "ecdh", "pbkdf2", "hkdf",
			"random", "x509", "tls", "jwt", "bcrypt",
		},
		"crypto.rs": {
			"md5", "sha1", "sha256", "sha512", "sha3", "blake", "hmac", "aes", "chacha20", "rsa", "ed25519",
			"ecdh", "pbkdf2", "bcrypt", "argon2", "hkdf", "tls", "x509", "jwt", "random",
		},
		"crypto.php": {
			"md5", "sha1", "sha256", "sha512", "sha3", "hmac", "aes", "3des", "chacha20", "rsa", "ed25519",
			"pbkdf2", "bcrypt", "argon2", "hkdf", "random", "x509", "ssh", "jwt",
		},
		"crypto.rb": {
			"md5", "sha1", "sha256", "sha512", "hmac", "aes", "3des", "rsa", "ecdsa", "pbkdf2", "scrypt", "hkdf",
			"bcrypt", "random", "tls", "x509", "jwt",
		},
	}
	for file, algorithms := range cases {
		t.Run(file, func(t *testing.T) {
			var got []string
			for _, id := range fixtureMatches(t, "crypto", file, "cryptography") {
				got = append(got, strings.TrimPrefix(id, "crypto."))
			}
			assert.Empty(t, missing(algorithms, got), "algorithms that do not match")
			assert.Empty(t, missing(got, algorithms), "algorithms that match and should not")
		})
	}
}

// fixtureMatches runs the embedded signatures on testdata/<dir>/<file> and
// returns the ids of the matched signatures that have the tag, each once.
func fixtureMatches(t *testing.T, dir, file, tag string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", dir, file))
	require.NoError(t, err)
	root := t.TempDir()
	write(t, root, file, string(data))

	a, err := defaultAnalyzer(context.Background(), root)
	require.NoError(t, err)
	var ids []string
	for _, m := range a.Matches {
		if slices.Contains(m.Signature.Tags, tag) && !slices.Contains(ids, m.Signature.ID) {
			ids = append(ids, m.Signature.ID)
		}
	}
	slices.Sort(ids)
	return ids
}

// missing returns the items of want that got does not have.
func missing(want, got []string) []string {
	var out []string
	for _, w := range want {
		if !slices.Contains(got, w) {
			out = append(out, w)
		}
	}
	return out
}
