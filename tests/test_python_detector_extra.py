"""Python-detector coverage for PyCryptodome, pyca Cipher modes, ssl, and KDF paths."""

from __future__ import annotations

from pathlib import PurePosixPath

from lattice.detectors.python_det import PythonDetector


def _detect(source: str):
    return list(PythonDetector().detect(PurePosixPath("sample.py"), source))


def test_pycryptodome_cipher_modes_and_key_inference():
    source = (
        "from Crypto.Cipher import AES, DES3, ARC4\n"
        "import os\n"
        "key = os.urandom(32)\n"
        "c1 = AES.new(key, AES.MODE_ECB)\n"
        "c2 = DES3.new(k2, DES3.MODE_CBC)\n"
        "c3 = ARC4.new(k3)\n"
    )
    by_algorithm = {a.algorithm: a for a in _detect(source)}
    assert set(by_algorithm) == {"AES-256", "3DES", "RC4"}
    assert by_algorithm["AES-256"].mode == "ECB"  # 32-byte urandom key inferred
    assert by_algorithm["3DES"].mode == "CBC"


def test_pycryptodome_publickey_and_hashes():
    source = (
        "from Crypto.PublicKey import RSA, ECC\n"
        "from Crypto.Hash import SHA1\n"
        "from Crypto.Protocol.KDF import PBKDF2\n"
        "k = RSA.generate(3072)\n"
        "e = ECC.generate(curve='P-256')\n"
        "h = SHA1.new()\n"
        "d = PBKDF2(password, salt, 32)\n"
    )
    by_algorithm = {a.algorithm: a for a in _detect(source)}
    assert set(by_algorithm) == {"RSA", "ECDSA", "SHA-1", "PBKDF2"}
    assert by_algorithm["RSA"].key_size == 3072
    assert by_algorithm["ECDSA"].curve == "P-256"


def test_pyca_cipher_keyword_args_and_curve():
    source = (
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "c = Cipher(algorithm=algorithms.TripleDES(key), mode=modes.CBC(iv))\n"
        "p = ec.generate_private_key(ec.SECP384R1())\n"
    )
    by_algorithm = {a.algorithm: a for a in _detect(source)}
    assert by_algorithm["3DES"].mode == "CBC"
    assert by_algorithm["ECDSA"].curve == "SECP384R1"


def test_ed25519_x25519_dh_and_kdfs():
    source = (
        "from cryptography.hazmat.primitives.asymmetric import ed25519, x25519, dh\n"
        "from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC\n"
        "from cryptography.hazmat.primitives.kdf.scrypt import Scrypt\n"
        "import bcrypt\n"
        "s = ed25519.Ed25519PrivateKey.generate()\n"
        "x = x25519.X25519PrivateKey.generate()\n"
        "params = dh.generate_parameters(generator=2, key_size=2048)\n"
        "kdf = PBKDF2HMAC(algorithm=None, length=32, salt=b's', iterations=600000)\n"
        "kdf2 = Scrypt(salt=b's', length=32, n=2**14, r=8, p=1)\n"
        "pw = bcrypt.hashpw(b'pw', bcrypt.gensalt())\n"
    )
    algorithms_found = {a.algorithm for a in _detect(source)}
    assert algorithms_found == {"EDDSA", "ECDH", "DH", "PBKDF2", "SCRYPT", "BCRYPT"}


def test_ssl_protocol_constants_and_cipher_strings():
    source = (
        "import ssl\n"
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n"
        "ctx.minimum_version = ssl.TLSVersion.TLSv1_1\n"
        "ctx.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256:RC4-SHA')\n"
    )
    found = {(a.algorithm, a.confidence.value) for a in _detect(source)}
    assert ("TLS-1.0", "high") in found
    assert ("TLS-1.1", "high") in found
    assert ("RC4", "medium") in found  # cipher-suite string parse is medium


def test_hashlib_new_pbkdf2_and_hmac():
    source = (
        "import hashlib, hmac\n"
        "h = hashlib.new('sha1')\n"
        "k = hashlib.pbkdf2_hmac('sha256', pw, salt, 600000)\n"
        "s = hashlib.scrypt(pw, salt=salt, n=16384, r=8, p=1)\n"
        "m = hmac.new(key, msg, 'sha256')\n"
        "b = hashlib.blake2b(b'x')\n"
    )
    algorithms_found = {a.algorithm for a in _detect(source)}
    assert algorithms_found == {"SHA-1", "PBKDF2", "SCRYPT", "HMAC", "BLAKE2"}


def test_dynamic_algorithm_selection_is_invisible_by_design():
    source = "import hashlib\nname = get_config()\nh = hashlib.new(name)\n"
    assert _detect(source) == []  # documented limitation: no guessing
