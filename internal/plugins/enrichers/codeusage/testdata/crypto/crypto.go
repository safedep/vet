package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh"
)

func All(key []byte) {
	md5.Sum(key)
	sha1.Sum(key)
	sha256.Sum256(key)
	sha512.Sum512(key)
	sha3.New256()
	hmac.New(sha256.New, key)
	block, _ := aes.NewCipher(key)
	cipher.NewGCM(block)
	des.NewTripleDESCipher(key)
	des.NewCipher(key)
	rc4.NewCipher(key)
	chacha20poly1305.New(key)
	rsa.GenerateKey(rand.Reader, 2048)
	ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ed25519.GenerateKey(rand.Reader)
	ecdh.X25519().GenerateKey(rand.Reader)
	pbkdf2.Key(key, key, 4096, 32, sha256.New)
	bcrypt.GenerateFromPassword(key, bcrypt.DefaultCost)
	scrypt.Key(key, key, 32768, 8, 1, 32)
	argon2.IDKey(key, key, 1, 64*1024, 4, 32)
	hkdf.New(sha256.New, key, nil, nil)
	rand.Read(key)
	tls.Dial("tcp", "example.com:443", &tls.Config{})
	ssh.ParsePrivateKey(key)
	x509.ParseCertificate(key)
	jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{})
}
