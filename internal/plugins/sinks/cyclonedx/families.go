package cyclonedx

// algorithmFamilies are the algorithm families of the CycloneDX 1.7
// cryptography registry. A family must be one of them, so an algorithm
// such as RSA, which the registry names only by scheme, has no family.
var algorithmFamilies = map[string]bool{
	"3DES": true, "3GPP-XOR": true, "A5/1": true, "A5/2": true, "AES": true, "ARIA": true, "Argon2": true,
	"Ascon": true, "BLAKE2": true, "BLAKE3": true, "BLS": true, "Blowfish": true, "CAMELLIA": true,
	"CAST5": true, "CAST6": true, "CMAC": true, "CMEA": true, "CTR_DRBG": true, "ChaCha": true,
	"ChaCha20": true, "DES": true, "DSA": true, "ECDH": true, "ECDSA": true, "ECIES": true, "EdDSA": true,
	"ElGamal": true, "FFDH": true, "Fortuna": true, "GOST": true, "HC": true, "HKDF": true, "HMAC": true,
	"HMAC_DRBG": true, "HPKE": true, "Hash_DRBG": true, "IDEA": true, "IKE-PRF": true, "J-PAKE": true,
	"LMS": true, "MD2": true, "MD4": true, "MD5": true, "MILENAGE": true, "ML-DSA": true, "ML-KEM": true,
	"MQV": true, "OPAQUE": true, "PBES1": true, "PBES2": true, "PBKDF1": true, "PBKDF2": true, "PBMAC1": true,
	"Poly1305": true, "RABBIT": true, "RC2": true, "RC4": true, "RC5": true, "RC6": true, "RIPEMD": true,
	"RSAES-OAEP": true, "RSAES-PKCS1": true, "RSASSA-PKCS1": true, "RSASSA-PSS": true, "SEED": true,
	"SHA-1": true, "SHA-2": true, "SHA-3": true, "SLH-DSA": true, "SM2": true, "SM3": true, "SM4": true,
	"SM9": true, "SNOW3G": true, "SP800-108": true, "SPAKE2": true, "SPAKE2PLUS": true, "SRP": true,
	"Salsa20": true, "Serpent": true, "SipHash": true, "Skipjack": true, "TUAK": true, "Twofish": true,
	"UMAC": true, "Whirlpool": true, "X3DH": true, "XMSS": true, "Yarrow": true, "ZUC": true, "bcrypt": true,
	"scrypt": true, "yescrypt": true,
}
