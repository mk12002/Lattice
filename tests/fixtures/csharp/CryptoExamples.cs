// Fixture: .NET crypto usage across the risk spectrum.
//
// Known answers (all medium confidence; type names intentionally not
// spelled out in this header so only the real code lines match):
// - the MD5 factory            -> MD5, P0 classically broken
// - the Aes factory + the ECB CipherMode reference in this file
//                              -> AES + ECB, P0 broken usage
// - the RSA factory (3072)     -> RSA 3072, P0 quantum-broken + HNDL
// - the AEAD GCM type          -> AES + GCM... but file-level ECB context does
//   not apply to it (intrinsic GCM), P2 (key size unknown)
// - the PBKDF2 deriver         -> PBKDF2, P2
using System;
using System.Security.Cryptography;

public static class CryptoExamples
{
    public static byte[] WeakDigest(byte[] data)
    {
        using var md5 = MD5.Create(); // KNOWN: MD5, P0
        return md5.ComputeHash(data);
    }

    public static ICryptoTransform LegacyCipher(byte[] key, byte[] iv)
    {
        var aes = Aes.Create(); // KNOWN: AES + ECB (from CipherMode below), P0
        aes.Mode = CipherMode.ECB;
        return aes.CreateEncryptor(key, iv);
    }

    public static RSA QuantumVulnerable()
    {
        return RSA.Create(3072); // KNOWN: RSA 3072, P0
    }

    public static byte[] ModernSeal(byte[] key, byte[] nonce, byte[] plaintext)
    {
        var sealed_ = new byte[plaintext.Length];
        var tag = new byte[16];
        using var gcm = new AesGcm(key); // KNOWN: AES + GCM, P2 (size unknown)
        gcm.Encrypt(nonce, plaintext, sealed_, tag);
        return sealed_;
    }

    public static byte[] DeriveKey(string password, byte[] salt)
    {
        using var kdf = new Rfc2898DeriveBytes(password, salt, 600_000); // KNOWN: PBKDF2, P2
        return kdf.GetBytes(32);
    }
}
