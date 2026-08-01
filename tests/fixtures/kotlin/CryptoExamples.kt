/*
 * Fixture: Kotlin JCA usage (handled by the Java detector, which applies to .kt).
 *
 * Known answers (medium confidence):
 * - MD5 (MessageDigest.getInstance)      -> P0 classically broken
 * - AES + ECB (Cipher.getInstance)       -> P0 broken usage
 * - RSA (KeyPairGenerator.getInstance)   -> P0 quantum-broken + HNDL
 * - ECDSA (Signature.getInstance)        -> P1 quantum-broken signature
 */
package com.example

import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import javax.crypto.Cipher

fun weakDigest(data: ByteArray): ByteArray =
    MessageDigest.getInstance("MD5").digest(data)          // KNOWN: MD5, P0

fun legacyCipher(): Cipher =
    Cipher.getInstance("AES/ECB/PKCS5Padding")             // KNOWN: AES + ECB, P0

fun quantumVulnerable(): KeyPairGenerator =
    KeyPairGenerator.getInstance("RSA")                    // KNOWN: RSA, P0

fun signer(): Signature =
    Signature.getInstance("SHA256withECDSA")               // KNOWN: ECDSA, P1
