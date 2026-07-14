/*
 * Fixture: node:crypto and library usage across the risk spectrum.
 *
 * Known answers (all medium confidence except the node-forge import,
 * which is high-confidence presence):
 * - SHA-1 (createHash)                    -> P0 classically broken
 * - AES-128 + ECB (createCipheriv triple) -> P0 broken usage
 * - RSA modulusLength 2048 (generateKeyPair) -> P0 quantum-broken + HNDL
 * - AES-256 + GCM (createCipheriv)        -> compliant
 * - PBKDF2 (crypto.pbkdf2)                -> P2
 * - node-forge import                     -> library inventory (none)
 */
const crypto = require('crypto');
const forge = require('node-forge'); // KNOWN: library inventory

function weakChecksum(data) {
  return crypto.createHash('sha1').update(data).digest('hex'); // KNOWN: SHA-1, P0
}

function legacyEncrypt(key, data) {
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null); // KNOWN: AES-128+ECB, P0
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function makeKeys(callback) {
  crypto.generateKeyPair('rsa', { modulusLength: 2048 }, callback); // KNOWN: RSA 2048, P0
}

function modernEncrypt(key, iv, data) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv); // KNOWN: AES-256+GCM, compliant
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function deriveKey(password, salt, callback) {
  crypto.pbkdf2(password, salt, 600000, 32, 'sha256', callback); // KNOWN: PBKDF2, P2
}

module.exports = { weakChecksum, legacyEncrypt, makeKeys, modernEncrypt, deriveKey };
