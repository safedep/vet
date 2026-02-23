package main

import (
	"crypto/aes"
	"crypto/sha256"
	"database/sql"
	"net/http"
	"os"
	"os/exec"
)

func main() {
	// Filesystem operations
	os.WriteFile("test.txt", []byte("hello"), 0o644)
	os.ReadFile("test.txt")
	os.Remove("test.txt")
	os.Mkdir("testdir", 0o755)

	// Network operations
	http.Get("https://example.com")
	http.ListenAndServe(":8080", nil)

	// Environment operations
	os.Getenv("HOME")
	os.Setenv("TEST", "value")

	// Process operations
	cmd := exec.Command("ls", "-la")
	cmd.Run()
	os.Getpid()

	// Cryptographic operations
	sha256.Sum256([]byte("data"))
	aes.NewCipher([]byte("key"))

	// Database operations
	sql.Open("postgres", "connection-string")
}
