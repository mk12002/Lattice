<?php
// Fixture: PHP crypto across the risk spectrum.
//
// Known answers (all medium confidence):
// - the sha1 hash call            -> SHA-1, P0 classically broken
// - the aes-128-ecb openssl call  -> AES-128 + ECB, P0 broken usage
// - the RSA keytype               -> RSA, P0 quantum-broken + HNDL
// - the aes-256-gcm openssl call  -> AES-256 + GCM, compliant
// - password_hash BCRYPT          -> BCRYPT, compliant

function weak_digest($data) {
    return hash('sha1', $data);                                   // KNOWN: SHA-1, P0
}

function legacy_cipher($data, $key) {
    return openssl_encrypt($data, 'aes-128-ecb', $key);          // KNOWN: AES-128 + ECB, P0
}

function quantum_vulnerable() {
    return openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA]);  // KNOWN: RSA, P0
}

function modern_seal($data, $key, $iv) {
    return openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv);  // KNOWN: AES-256 + GCM, compliant
}

function store_password($pw) {
    return password_hash($pw, PASSWORD_BCRYPT);                  // KNOWN: BCRYPT, compliant
}
