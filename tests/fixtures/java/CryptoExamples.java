/*
 * Fixture: JCA usage across the risk spectrum.
 *
 * Known answers (exactly these assets, all medium confidence except the
 * BouncyCastle import which is high-confidence presence):
 * - AES + ECB mode (Cipher.getInstance)      -> P0 broken usage
 * - MD5 (MessageDigest.getInstance)          -> P0 classically broken
 * - RSA (KeyPairGenerator.getInstance)       -> P0 quantum-broken + HNDL
 * - ECDSA (Signature.getInstance, signature) -> P1 quantum-broken, no HNDL
 * - HMAC (Mac.getInstance)                   -> compliant
 * - BouncyCastle import                      -> library inventory (none)
 */
package com.example;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoExamples {
    void legacyCipher() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // KNOWN: AES+ECB, P0
    }

    byte[] weakDigest(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data); // KNOWN: MD5, P0
    }

    KeyPairGenerator quantumVulnerable() throws Exception {
        return KeyPairGenerator.getInstance("RSA"); // KNOWN: RSA, P0 (HNDL)
    }

    Signature signer() throws Exception {
        return Signature.getInstance("SHA256withECDSA"); // KNOWN: ECDSA, P1
    }

    Mac mac() throws Exception {
        return Mac.getInstance("HmacSHA256"); // KNOWN: HMAC, compliant
    }
}
