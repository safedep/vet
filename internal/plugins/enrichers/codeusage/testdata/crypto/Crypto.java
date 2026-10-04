import java.security.MessageDigest;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import org.mindrot.jbcrypt.BCrypt;
import io.jsonwebtoken.Jwts;

class Crypto {
  void all(byte[] key) throws Exception {
    MessageDigest.getInstance("MD5");
    MessageDigest.getInstance("SHA-1");
    MessageDigest.getInstance("SHA-256");
    MessageDigest.getInstance("SHA-512");
    Mac.getInstance("HmacSHA256");
    Cipher.getInstance("AES/GCM/NoPadding");
    Cipher.getInstance("DESede/CBC/PKCS5Padding");
    new SecretKeySpec(key, "DES");
    KeyPairGenerator.getInstance("RSA");
    KeyPairGenerator.getInstance("EC");
    Signature.getInstance("Ed25519");
    KeyAgreement.getInstance("ECDH");
    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    BCrypt.hashpw("p", BCrypt.gensalt());
    new SecureRandom();
    SSLContext.getInstance("TLSv1.3");
    CertificateFactory.getInstance("X.509");
    Jwts.builder();
  }
}
