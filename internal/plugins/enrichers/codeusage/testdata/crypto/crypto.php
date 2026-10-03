<?php
namespace App\Security;

use Firebase\JWT\JWT;
use phpseclib3\Crypt\RSA;
use phpseclib3\Net\SSH2;

class Vault
{
    public function all(string $data, string $key, string $iv): void
    {
        md5($data);
        sha1($data);
        hash('sha256', $data);
        hash("sha512", $data);
        hash('sha3-256', $data);
        hash_hmac('sha256', $data, $key);
        openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv);
        openssl_encrypt($data, "des-ede3-cbc", $key, 0, $iv);
        sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($data, '', $iv, $key);
        RSA::createKey(2048);
        sodium_crypto_sign_keypair();
        hash_pbkdf2('sha256', $data, $key, 100000);
        password_hash($data, PASSWORD_DEFAULT);
        sodium_crypto_pwhash_str($data, 4, 1 << 26);
        hash_hkdf('sha256', $key);
        random_bytes(32);
        openssl_x509_read($data);
        new SSH2('example.com');
        JWT::encode([], $key, 'HS256');
    }
}
