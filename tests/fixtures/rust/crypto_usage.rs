// Fixture: Rust crypto usage across the risk spectrum.
//
// Known answers (all medium confidence; crate/token names intentionally not
// spelled out in this header so only the real code lines match):
// - the md5 crate use            -> MD5, P0 classically broken
// - the openssl aes-128-ecb call -> AES-128 + ECB, P0 broken usage
// - the openssl RSA keygen       -> RSA 2048, P0 quantum-broken + HNDL
// - the aes-gcm crate use        -> AES + GCM (key size unknown), P2
// - the chacha20poly1305 use     -> CHACHA20, compliant

use md5::{Digest, Md5}; // KNOWN: MD5, P0
use aes_gcm::Aes256Gcm; // KNOWN: AES + GCM (size not inferred from crate), P2
use chacha20poly1305::ChaCha20Poly1305; // KNOWN: CHACHA20, compliant
use openssl::symm::Cipher;
use openssl::rsa::Rsa;

fn weak_checksum(data: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn legacy_cipher() -> Cipher {
    Cipher::aes_128_ecb() // KNOWN: AES-128 + ECB, P0
}

fn quantum_vulnerable() -> Rsa<openssl::pkey::Private> {
    Rsa::generate(2048).unwrap() // KNOWN: RSA 2048, P0
}
