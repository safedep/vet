require 'openssl'
require 'digest'
require 'securerandom'
require 'bcrypt'
require 'jwt'

class Vault
  def all(data, key)
    Digest::MD5.hexdigest(data)
    Digest::SHA1.hexdigest(data)
    Digest::SHA256.hexdigest(data)
    OpenSSL::Digest.new('SHA512')
    OpenSSL::HMAC.hexdigest('SHA256', key, data)
    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    OpenSSL::Cipher.new('des-ede3-cbc')
    OpenSSL::PKey::RSA.generate(2048)
    OpenSSL::PKey::EC.generate('prime256v1')
    OpenSSL::PKCS5.pbkdf2_hmac(key, 'salt', 100_000, 32, 'sha256')
    OpenSSL::KDF.scrypt(key, salt: 'salt', N: 16_384, r: 8, p: 1, length: 32)
    OpenSSL::KDF.hkdf(key, salt: 'salt', info: 'i', length: 32, hash: 'SHA256')
    BCrypt::Password.create(data)
    SecureRandom.hex(32)
    OpenSSL::SSL::SSLContext.new
    OpenSSL::X509::Certificate.new(data)
    JWT.encode({}, key, 'HS256')
  end
end
