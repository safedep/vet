const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const tls = require('tls');
import CryptoJS from 'crypto-js';
import { SignJWT } from 'jose';

export function digests(data, key) {
  crypto.createHash('md5').update(data).digest('hex');
  crypto.createHash("sha1").update(data);
  crypto.createHash('sha256').update(data).digest();
  crypto.createHash('sha512');
  crypto.createHmac('sha256', key).update(data).digest('hex');
  CryptoJS.SHA3(data);
}

export async function ciphers(key, iv) {
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  crypto.createCipheriv('des-ede3-cbc', key, iv);
  CryptoJS.RC4.encrypt('x', 'k');
  crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  crypto.generateKeyPairSync('ed25519');
  crypto.createECDH('prime256v1');
  crypto.pbkdf2Sync('p', 's', 100000, 32, 'sha256');
  crypto.scryptSync('p', 's', 32);
  crypto.hkdfSync('sha256', key, 's', 'i', 32);
  await bcrypt.hash('p', 12);
  crypto.randomBytes(32);
  tls.connect(443, 'example.com');
  new crypto.X509Certificate(key);
  jwt.sign({}, 'k');
  await new SignJWT({}).sign(key);
}
