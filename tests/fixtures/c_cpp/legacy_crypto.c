/*
 * Fixture: OpenSSL usage across the risk spectrum.
 *
 * Known answers (all medium confidence; function names intentionally not
 * spelled out here so the token scanner only sees the real call sites):
 * - the md5 EVP digest        -> MD5, P0 classically broken
 * - the aes 128 ecb EVP cipher -> AES-128 + ECB, P0 broken usage
 * - the RSA keygen call        -> RSA, P0 quantum-broken + HNDL
 * - the aes 256 gcm EVP cipher -> AES-256 + GCM, compliant
 */
#include <openssl/evp.h>
#include <openssl/rsa.h>

void weak_digest(void) {
    const EVP_MD *md = EVP_md5(); /* KNOWN: MD5, P0 */
    (void)md;
}

void legacy_cipher(void) {
    const EVP_CIPHER *cipher = EVP_aes_128_ecb(); /* KNOWN: AES-128+ECB, P0 */
    (void)cipher;
}

int quantum_vulnerable(RSA *rsa, BIGNUM *e) {
    return RSA_generate_key_ex(rsa, 2048, e, NULL); /* KNOWN: RSA, P0 */
}

void modern_cipher(void) {
    const EVP_CIPHER *cipher = EVP_aes_256_gcm(); /* KNOWN: AES-256+GCM, compliant */
    (void)cipher;
}
