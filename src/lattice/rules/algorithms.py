"""The cryptographic knowledge base.

This table encodes Lattice's entire cryptographic judgment. Every entry is a
well-established cryptographic fact (e.g. Shor's algorithm breaks RSA/ECC;
MD5 and SHA-1 are collision-broken; Grover's algorithm halves the effective
strength of symmetric keys). Standards are referenced by name only (NIST
FIPS 203/204/205); no CVE numbers, CVSS scores, or statistics appear here
because none can be grounded from static rules.

Consistency invariant (tested): an entry that is quantum-SAFE *and*
classically SECURE is already a migration target and must not carry a
``pqc_replacement``.

Canonical naming: uppercase canonical names ("RSA", "AES-128", "SHA-256",
"ML-KEM"). ``lookup()`` normalizes case/separators and resolves the synonym
map, so detectors may pass raw strings like ``"aes_128"`` or ``"prime256v1"``.
"""

from __future__ import annotations

from dataclasses import dataclass

from lattice.core.models import ClassicalStatus, Family, QuantumStatus


@dataclass(frozen=True)
class AlgorithmInfo:
    """Static facts about one canonical algorithm."""

    name: str
    family: Family
    quantum_status: QuantumStatus
    classical_status: ClassicalStatus
    pqc_replacement: str | None
    notes: str


def _e(
    name: str,
    family: Family,
    quantum: QuantumStatus,
    classical: ClassicalStatus,
    replacement: str | None,
    notes: str,
) -> tuple[str, AlgorithmInfo]:
    return name, AlgorithmInfo(name, family, quantum, classical, replacement, notes)


_Q = QuantumStatus
_C = ClassicalStatus
_F = Family

#: canonical name -> AlgorithmInfo. Rationale is carried in each entry's notes.
ALGORITHMS: dict[str, AlgorithmInfo] = dict(
    [
        # ------------------------------------------------------------------
        # Asymmetric encryption / key exchange / signatures: broken by Shor.
        # ------------------------------------------------------------------
        _e(
            "RSA",
            _F.ASYMMETRIC_CIPHER,
            _Q.BROKEN,
            _C.SECURE,
            "ML-KEM (FIPS 203) for encryption/key transport; ML-DSA (FIPS 204) for signatures",
            "Integer factorization is broken by Shor's algorithm on a cryptographically "
            "relevant quantum computer. Classically secure at >=2048 bits today.",
        ),
        _e(
            "DH",
            _F.KEY_EXCHANGE,
            _Q.BROKEN,
            _C.SECURE,
            "ML-KEM (FIPS 203)",
            "Finite-field discrete log is broken by Shor's algorithm. Key agreements "
            "captured today are decryptable once such a machine exists (HNDL).",
        ),
        _e(
            "ECDH",
            _F.KEY_EXCHANGE,
            _Q.BROKEN,
            _C.SECURE,
            "ML-KEM (FIPS 203)",
            "Elliptic-curve discrete log is broken by Shor's algorithm; applies to all "
            "curves including X25519/X448.",
        ),
        _e(
            "ECDSA",
            _F.SIGNATURE,
            _Q.BROKEN,
            _C.SECURE,
            "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)",
            "Elliptic-curve discrete log is broken by Shor's algorithm; applies to all "
            "NIST and non-NIST curves.",
        ),
        _e(
            "EDDSA",
            _F.SIGNATURE,
            _Q.BROKEN,
            _C.SECURE,
            "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)",
            "Edwards-curve signatures (Ed25519/Ed448) rest on elliptic-curve discrete "
            "log, broken by Shor's algorithm.",
        ),
        _e(
            "DSA",
            _F.SIGNATURE,
            _Q.BROKEN,
            _C.DEPRECATED,
            "ML-DSA (FIPS 204)",
            "Finite-field discrete log, broken by Shor's algorithm; deprecated for new "
            "use classically as well.",
        ),
        _e(
            "ELGAMAL",
            _F.ASYMMETRIC_CIPHER,
            _Q.BROKEN,
            _C.DEPRECATED,
            "ML-KEM (FIPS 203)",
            "Discrete-log encryption, broken by Shor's algorithm; rarely appropriate "
            "for new designs classically.",
        ),
        # ------------------------------------------------------------------
        # Post-quantum standards: the migration targets.
        # ------------------------------------------------------------------
        _e(
            "ML-KEM",
            _F.KEY_EXCHANGE,
            _Q.SAFE,
            _C.SECURE,
            None,
            "Module-lattice KEM standardized as NIST FIPS 203 (from CRYSTALS-Kyber). "
            "The primary post-quantum key-establishment target.",
        ),
        _e(
            "ML-DSA",
            _F.SIGNATURE,
            _Q.SAFE,
            _C.SECURE,
            None,
            "Module-lattice signature standardized as NIST FIPS 204 (from "
            "CRYSTALS-Dilithium). The primary post-quantum signature target.",
        ),
        _e(
            "SLH-DSA",
            _F.SIGNATURE,
            _Q.SAFE,
            _C.SECURE,
            None,
            "Stateless hash-based signature standardized as NIST FIPS 205 (from "
            "SPHINCS+). Conservative post-quantum signature choice.",
        ),
        _e(
            "FALCON",
            _F.SIGNATURE,
            _Q.SAFE,
            _C.SECURE,
            None,
            "NTRU-lattice signature selected by NIST; standardization (as FN-DSA) is "
            "still in progress, noted as such.",
        ),
        # ------------------------------------------------------------------
        # Symmetric ciphers: Grover halves effective key strength.
        # ------------------------------------------------------------------
        _e(
            "AES-256",
            _F.SYMMETRIC_CIPHER,
            _Q.SAFE,
            _C.SECURE,
            None,
            "256-bit keys retain ~128-bit effective strength under Grover's algorithm; "
            "considered quantum-resistant.",
        ),
        _e(
            "AES-192",
            _F.SYMMETRIC_CIPHER,
            _Q.WEAKENED,
            _C.SECURE,
            "AES-256",
            "Grover's algorithm reduces effective strength to ~96 bits; move to "
            "256-bit keys for long-lived data.",
        ),
        _e(
            "AES-128",
            _F.SYMMETRIC_CIPHER,
            _Q.WEAKENED,
            _C.SECURE,
            "AES-256",
            "Grover's algorithm reduces effective strength to ~64 bits in theory; "
            "move to 256-bit keys for long-lived data.",
        ),
        _e(
            "AES",
            _F.SYMMETRIC_CIPHER,
            _Q.WEAKENED,
            _C.SECURE,
            "AES-256",
            "AES with key size not determined from the call site; treated "
            "conservatively as <256-bit until the key size is confirmed.",
        ),
        _e(
            "CHACHA20",
            _F.SYMMETRIC_CIPHER,
            _Q.SAFE,
            _C.SECURE,
            None,
            "256-bit stream cipher (usually as ChaCha20-Poly1305 AEAD); retains "
            "adequate margin under Grover's algorithm.",
        ),
        _e(
            "3DES",
            _F.SYMMETRIC_CIPHER,
            _Q.WEAKENED,
            _C.DEPRECATED,
            "AES-256",
            "Deprecated classically (64-bit blocks, Sweet32-style collision exposure, "
            "withdrawn by NIST for new use); replace with AES-256.",
        ),
        _e(
            "DES",
            _F.SYMMETRIC_CIPHER,
            _Q.WEAKENED,
            _C.BROKEN,
            "AES-256",
            "56-bit key is exhaustively searchable with classical hardware; broken "
            "today independent of quantum computing.",
        ),
        _e(
            "RC4",
            _F.SYMMETRIC_CIPHER,
            _Q.NA,
            _C.BROKEN,
            "AES-256 (GCM) or ChaCha20-Poly1305",
            "Keystream biases make RC4 exploitable in practice; prohibited in TLS. "
            "Broken today independent of quantum computing.",
        ),
        _e(
            "RC2",
            _F.SYMMETRIC_CIPHER,
            _Q.WEAKENED,
            _C.DEPRECATED,
            "AES-256",
            "Legacy 64-bit-block cipher with known related-key attacks; deprecated for new use.",
        ),
        _e(
            "BLOWFISH",
            _F.SYMMETRIC_CIPHER,
            _Q.WEAKENED,
            _C.DEPRECATED,
            "AES-256",
            "64-bit block size makes long sessions collision-prone (Sweet32-style); "
            "its own author recommends successors.",
        ),
        # ------------------------------------------------------------------
        # Hashes: collisions break MD5/SHA-1 today; Grover halves preimage margin.
        # ------------------------------------------------------------------
        _e(
            "MD5",
            _F.HASH,
            _Q.NA,
            _C.BROKEN,
            "SHA-256 or stronger (SHA-384/SHA-3 preferred long-term)",
            "Practical collision attacks exist; unfit for any security purpose today.",
        ),
        _e(
            "SHA-1",
            _F.HASH,
            _Q.NA,
            _C.BROKEN,
            "SHA-256 or stronger (SHA-384/SHA-3 preferred long-term)",
            "Practical collision attacks demonstrated (chosen-prefix collisions); "
            "retired by NIST for security use.",
        ),
        _e(
            "SHA-256",
            _F.HASH,
            _Q.WEAKENED,
            _C.SECURE,
            "SHA-384, SHA-512, or SHA-3 for new long-lived designs",
            "Secure today; Grover's algorithm halves the preimage margin, so larger "
            "output sizes are preferred for long-term post-quantum designs.",
        ),
        _e(
            "SHA-384",
            _F.HASH,
            _Q.SAFE,
            _C.SECURE,
            None,
            "Retains >=192-bit preimage margin under Grover's algorithm; a preferred "
            "post-quantum hash size.",
        ),
        _e(
            "SHA-512",
            _F.HASH,
            _Q.SAFE,
            _C.SECURE,
            None,
            "Retains >=256-bit preimage margin under Grover's algorithm.",
        ),
        _e(
            "SHA-3",
            _F.HASH,
            _Q.SAFE,
            _C.SECURE,
            None,
            "Keccak-based FIPS 202 family (SHA3-256/384/512, SHAKE); no known "
            "classical weaknesses and adequate quantum margins at >=256-bit output.",
        ),
        _e(
            "BLAKE2",
            _F.HASH,
            _Q.SAFE,
            _C.SECURE,
            None,
            "Modern hash with no known practical attacks; 256/512-bit outputs give "
            "adequate quantum margins.",
        ),
        _e(
            "BLAKE3",
            _F.HASH,
            _Q.SAFE,
            _C.SECURE,
            None,
            "Modern tree hash with no known practical attacks; 256-bit default output.",
        ),
        # ------------------------------------------------------------------
        # Protocol versions (flagged by the config and language detectors).
        # ------------------------------------------------------------------
        _e(
            "SSL-2.0",
            _F.PROTOCOL,
            _Q.NA,
            _C.BROKEN,
            "TLS 1.2 or newer (prefer TLS 1.3)",
            "Fundamentally broken handshake and integrity protection (DROWN class); prohibited.",
        ),
        _e(
            "SSL-3.0",
            _F.PROTOCOL,
            _Q.NA,
            _C.BROKEN,
            "TLS 1.2 or newer (prefer TLS 1.3)",
            "Broken by practical padding-oracle attacks (POODLE class); prohibited.",
        ),
        _e(
            "TLS-1.0",
            _F.PROTOCOL,
            _Q.NA,
            _C.DEPRECATED,
            "TLS 1.2 or newer (prefer TLS 1.3)",
            "Formally deprecated (RFC 8996); lacks modern AEAD cipher suites.",
        ),
        _e(
            "TLS-1.1",
            _F.PROTOCOL,
            _Q.NA,
            _C.DEPRECATED,
            "TLS 1.2 or newer (prefer TLS 1.3)",
            "Formally deprecated (RFC 8996); lacks modern AEAD cipher suites.",
        ),
        _e(
            "TLS-1.2",
            _F.PROTOCOL,
            _Q.NA,
            _C.SECURE,
            None,
            "Acceptable when configured with AEAD suites; quantum exposure comes from "
            "the negotiated key exchange, which is inventoried separately.",
        ),
        _e(
            "TLS-1.3",
            _F.PROTOCOL,
            _Q.NA,
            _C.SECURE,
            None,
            "Current TLS version; hybrid post-quantum key-exchange deployments build on it.",
        ),
        # ------------------------------------------------------------------
        # KDFs / password hashing / MAC.
        # ------------------------------------------------------------------
        _e(
            "ARGON2",
            _F.KDF,
            _Q.SAFE,
            _C.SECURE,
            None,
            "Memory-hard password hash (Password Hashing Competition winner); the "
            "recommended choice for new password storage.",
        ),
        _e(
            "SCRYPT",
            _F.KDF,
            _Q.SAFE,
            _C.SECURE,
            None,
            "Memory-hard KDF; sound with adequate cost parameters.",
        ),
        _e(
            "BCRYPT",
            _F.KDF,
            _Q.SAFE,
            _C.SECURE,
            None,
            "Sound with adequate cost factor; note the 72-byte input limit.",
        ),
        _e(
            "PBKDF2",
            _F.KDF,
            _Q.WEAKENED,
            _C.SECURE,
            "Higher iteration counts, or migrate to Argon2id",
            "Not memory-hard, so GPU/ASIC attackers scale well against it; secure "
            "only with high iteration counts. Grover further halves the brute-force "
            "margin for short passwords.",
        ),
        _e(
            "HMAC",
            _F.MAC,
            _Q.SAFE,
            _C.SECURE,
            None,
            "Security rests on the underlying hash's PRF property, which survives "
            "known quantum attacks with adequate key/output sizes. Pair with SHA-256+.",
        ),
    ]
)

#: raw synonym -> canonical name. Keys are stored normalized (see _normalize).
SYNONYMS: dict[str, str] = {
    # RSA and its paddings / OID-ish names
    "rsaencryption": "RSA",
    "pkcs1": "RSA",
    "rsa-oaep": "RSA",
    "rsa-oaep-256": "RSA",
    "rsaes-oaep": "RSA",
    "rsa-pss": "RSA",
    "rsassa-pss": "RSA",
    "rsa-pkcs1-v1-5": "RSA",
    # Diffie-Hellman
    "diffie-hellman": "DH",
    "diffiehellman": "DH",
    "dhe": "DH",
    "ffdhe": "DH",
    "x9-42": "DH",
    # ECDH and Montgomery-curve agreement
    "ecdhe": "ECDH",
    "x25519": "ECDH",
    "x448": "ECDH",
    "curve25519": "ECDH",
    "ecmqv": "ECDH",
    # ECDSA and named curves (a curve name in a keygen/sign context implies ECC)
    "ec": "ECDSA",
    "ecc": "ECDSA",
    "secp192r1": "ECDSA",
    "secp224r1": "ECDSA",
    "secp256r1": "ECDSA",
    "prime256v1": "ECDSA",
    "secp384r1": "ECDSA",
    "secp521r1": "ECDSA",
    "secp256k1": "ECDSA",
    "p-256": "ECDSA",
    "p-384": "ECDSA",
    "p-521": "ECDSA",
    "nistp256": "ECDSA",
    "nistp384": "ECDSA",
    "nistp521": "ECDSA",
    "brainpoolp256r1": "ECDSA",
    "brainpoolp384r1": "ECDSA",
    "brainpoolp512r1": "ECDSA",
    # EdDSA
    "ed25519": "EDDSA",
    "ed448": "EDDSA",
    # ElGamal
    "elgamal": "ELGAMAL",
    # PQC names
    "kyber": "ML-KEM",
    "kyber512": "ML-KEM",
    "kyber768": "ML-KEM",
    "kyber1024": "ML-KEM",
    "ml-kem-512": "ML-KEM",
    "ml-kem-768": "ML-KEM",
    "ml-kem-1024": "ML-KEM",
    "crystals-kyber": "ML-KEM",
    "dilithium": "ML-DSA",
    "dilithium2": "ML-DSA",
    "dilithium3": "ML-DSA",
    "dilithium5": "ML-DSA",
    "crystals-dilithium": "ML-DSA",
    "ml-dsa-44": "ML-DSA",
    "ml-dsa-65": "ML-DSA",
    "ml-dsa-87": "ML-DSA",
    "sphincs+": "SLH-DSA",
    "sphincs": "SLH-DSA",
    "sphincsplus": "SLH-DSA",
    "fn-dsa": "FALCON",
    "falcon512": "FALCON",
    "falcon1024": "FALCON",
    # AES
    "rijndael": "AES",
    "aes128": "AES-128",
    "aes192": "AES-192",
    "aes256": "AES-256",
    # ChaCha
    "chacha20-poly1305": "CHACHA20",
    "xchacha20": "CHACHA20",
    "xchacha20-poly1305": "CHACHA20",
    "chacha": "CHACHA20",
    # 3DES / DES
    "tripledes": "3DES",
    "triple-des": "3DES",
    "desede": "3DES",
    "des3": "3DES",
    "des-ede": "3DES",
    "des-ede3": "3DES",
    "tdea": "3DES",
    # RC4
    "arc4": "RC4",
    "arcfour": "RC4",
    "rc4-40": "RC4",
    # Blowfish
    "bf": "BLOWFISH",
    # Hashes
    "md-5": "MD5",
    "sha1": "SHA-1",
    "sha": "SHA-1",  # bare "SHA" in JCA algorithm strings means SHA-1
    "sha256": "SHA-256",
    "sha2-256": "SHA-256",
    "sha384": "SHA-384",
    "sha2-384": "SHA-384",
    "sha512": "SHA-512",
    "sha2-512": "SHA-512",
    "sha3-224": "SHA-3",
    "sha3-256": "SHA-3",
    "sha3-384": "SHA-3",
    "sha3-512": "SHA-3",
    "shake": "SHA-3",
    "shake128": "SHA-3",
    "shake256": "SHA-3",
    "keccak": "SHA-3",
    "blake2b": "BLAKE2",
    "blake2s": "BLAKE2",
    # Protocol versions
    "sslv2": "SSL-2.0",
    "ssl2": "SSL-2.0",
    "sslv2.0": "SSL-2.0",
    "sslv3": "SSL-3.0",
    "ssl3": "SSL-3.0",
    "sslv3.0": "SSL-3.0",
    "tlsv1": "TLS-1.0",
    "tlsv1.0": "TLS-1.0",
    "tls1.0": "TLS-1.0",
    "tls10": "TLS-1.0",
    "tlsv1.1": "TLS-1.1",
    "tls1.1": "TLS-1.1",
    "tls11": "TLS-1.1",
    "tlsv1.2": "TLS-1.2",
    "tls1.2": "TLS-1.2",
    "tls12": "TLS-1.2",
    "tlsv1.3": "TLS-1.3",
    "tls1.3": "TLS-1.3",
    "tls13": "TLS-1.3",
    # KDFs
    "argon2id": "ARGON2",
    "argon2i": "ARGON2",
    "argon2d": "ARGON2",
    "pbkdf2hmac": "PBKDF2",
    "pbkdf2-hmac-sha256": "PBKDF2",
    "eddsa": "EDDSA",
}


def _normalize(name: str) -> str:
    """Normalize a raw algorithm string for lookup: lowercase, unify separators."""
    return name.strip().lower().replace("_", "-").replace(" ", "-")


def lookup(name: str) -> AlgorithmInfo | None:
    """Resolve a raw algorithm name (canonical or synonym) to its knowledge-base entry.

    Returns ``None`` for unknown names — callers must treat unknown as
    "inventory without judgment", never guess.
    """
    if not name:
        return None
    norm = _normalize(name)
    canonical = SYNONYMS.get(norm)
    if canonical is not None:
        return ALGORITHMS[canonical]
    # canonical names themselves normalize to their lowercase form
    for canon, info in ALGORITHMS.items():
        if _normalize(canon) == norm:
            return info
    return None


def all_canonical_names() -> list[str]:
    """All canonical algorithm names, sorted (for ``lattice rules list``)."""
    return sorted(ALGORITHMS)
