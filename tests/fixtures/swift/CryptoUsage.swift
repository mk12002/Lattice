// Fixture: Swift CryptoKit usage across the risk spectrum.
//
// Known answers (all medium confidence). The header avoids the API tokens
// the detector matches on, so only the real call sites below are counted:
// - the insecure legacy digest    -> MD5, P0 classically broken
// - the X25519 key agreement       -> ECDH, P0 quantum-broken + HNDL
// - the P-256 signing key          -> ECDSA, P1 quantum-broken signature
// - the AES-GCM seal               -> AES + GCM, P2 (key size not determinable)
// - the ChaCha-Poly seal           -> CHACHA20, compliant

import CryptoKit

func weakDigest(_ data: Data) -> Data {
    return Data(Insecure.MD5.hash(data: data))            // KNOWN: MD5, P0
}

func keyAgreement() {
    let sk = Curve25519.KeyAgreement.PrivateKey()         // KNOWN: ECDH, P0 (HNDL)
    _ = sk
}

func signingKey() {
    let sk = P256.Signing.PrivateKey()                    // KNOWN: ECDSA, P1
    _ = sk
}

func modernSeal(_ data: Data, _ key: SymmetricKey) throws -> Data {
    return try AES.GCM.seal(data, using: key).combined!   // KNOWN: AES + GCM, P2
}

func streamSeal(_ data: Data, _ key: SymmetricKey) throws -> Data {
    return try ChaChaPoly.seal(data, using: key).combined // KNOWN: CHACHA20, compliant
}
