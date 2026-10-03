using System.IdentityModel.Tokens.Jwt;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public class CryptoUse
{
    public void All(byte[] key, System.IO.Stream stream)
    {
        MD5.HashData(key);
        using var sha1 = SHA1.Create();
        SHA256.HashData(key);
        SHA512.HashData(key);
        using var hmac = new HMACSHA256(key);
        using var aes = Aes.Create();
        using var gcm = new AesGcm(key, 16);
        using var tdes = TripleDES.Create();
        using var rsa = RSA.Create(2048);
        using var ecdsa = ECDsa.Create();
        using var ecdh = ECDiffieHellman.Create();
        using var kdf = new Rfc2898DeriveBytes("p", key, 600000, HashAlgorithmName.SHA256);
        HKDF.DeriveKey(HashAlgorithmName.SHA256, key, 32);
        RandomNumberGenerator.GetBytes(32);
        var cert = new X509Certificate2(key);
        var tls = new SslStream(stream);
        var handler = new JwtSecurityTokenHandler();
        var hash = BCrypt.Net.BCrypt.HashPassword("p");
    }
}
