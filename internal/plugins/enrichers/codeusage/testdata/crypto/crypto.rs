use aes_gcm::{Aes256Gcm, KeyInit};
use argon2::Argon2;
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

fn all(key: &[u8]) {
    let a = md5::compute(key);
    let b = Sha1::digest(key);
    let c = Sha256::digest(key);
    let d = Sha512::new();
    let e = sha3::Sha3_256::digest(key);
    let f = blake3::hash(key);
    let mac = Hmac::<Sha256>::new_from_slice(key);
    let g = Aes256Gcm::new_from_slice(key);
    let h = ChaCha20Poly1305::new_from_slice(key);
    let k = RsaPrivateKey::new(&mut OsRng, 2048);
    let s = SigningKey::generate(&mut OsRng);
    let x = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let p = pbkdf2::pbkdf2_hmac::<Sha256>(key, b"salt", 600_000, &mut [0u8; 32]);
    let q = bcrypt::hash("p", 12);
    let r = Argon2::default();
    let t = hkdf::Hkdf::<Sha256>::new(None, key);
    let u = rustls::ClientConfig::builder();
    let v = x509_parser::parse_x509_certificate(key);
    let w = jsonwebtoken::encode(&header, &claims, &enc);
    let n = getrandom::fill(&mut [0u8; 16]);
}
