import hashlib, hmac, secrets, ssl
import bcrypt, jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
from Crypto.Cipher import DES, ARC4
from argon2 import PasswordHasher


def digests(data, key):
    hashlib.md5(data)
    hashlib.new("sha1", data)
    hashlib.sha256(data)
    hashlib.sha512(data)
    hashlib.sha3_256(data)
    hashlib.blake2b(data)
    hmac.new(key, data, hashlib.sha256)
    hashlib.scrypt(data, salt=key, n=16384, r=8, p=1)


def ciphers(key):
    AESGCM(key)
    ChaCha20Poly1305(key)
    DES.new(key, DES.MODE_ECB)
    ARC4.new(key)
    rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec.generate_private_key(ec.SECP256R1())
    ed25519.Ed25519PrivateKey.generate()
    x25519.X25519PrivateKey.generate()
    PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=key, iterations=600000)
    HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"x")
    bcrypt.hashpw(key, bcrypt.gensalt())
    PasswordHasher().hash("x")
    secrets.token_bytes(32)
    ssl.create_default_context()
    x509.load_pem_x509_certificate(key)
    jwt.encode({}, key, algorithm="HS256")
