"""Python detector: AST-aware matching of crypto usage, regex fallback for the rest.

Recognizes the stdlib (``hashlib``, ``hmac``, ``ssl``), pyca ``cryptography``
(hazmat primitives and AEAD classes), and PyCryptodome (``Crypto``/
``Cryptodome``). AST matches are HIGH confidence; algorithm strings parsed
out of ``ssl.set_ciphers`` are MEDIUM; token scans of unparseable files are
LOW.

Deliberate scope limits (documented in README Limitations): dynamically
selected algorithms (``hashlib.new(user_choice)``) and key sizes that only
exist at runtime cannot be seen statically. AES with an undeterminable key
size is reported as bare ``AES`` (conservatively treated as <256-bit).
Protocol constants are reported only when below TLS 1.2.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Iterator
from pathlib import PurePath

from lattice.core.models import Confidence, CryptoAsset, Family
from lattice.detectors.base import Detector, make_snippet, regex_fallback_scan

#: hashlib constructor name -> canonical algorithm
_HASHLIB_FUNCS = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha224": "SHA-256",  # SHA-2 family; nearest canonical entry
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha3_224": "SHA-3",
    "sha3_256": "SHA-3",
    "sha3_384": "SHA-3",
    "sha3_512": "SHA-3",
    "shake_128": "SHA-3",
    "shake_256": "SHA-3",
    "blake2b": "BLAKE2",
    "blake2s": "BLAKE2",
}

#: PyCryptodome cipher module -> (canonical algorithm, fixed key bits or None)
_PYCRYPTODOME_CIPHERS = {
    "AES": ("AES", None),
    "DES": ("DES", 64),
    "DES3": ("3DES", None),
    "ARC4": ("RC4", None),
    "Blowfish": ("BLOWFISH", None),
    "ChaCha20": ("CHACHA20", 256),
    "ChaCha20_Poly1305": ("CHACHA20", 256),
    "Salsa20": ("CHACHA20", 256),
}

_PYCRYPTODOME_HASHES = {
    "MD5": "MD5",
    "SHA1": "SHA-1",
    "SHA256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA512": "SHA-512",
    "SHA3_256": "SHA-3",
    "SHA3_512": "SHA-3",
    "BLAKE2b": "BLAKE2",
    "BLAKE2s": "BLAKE2",
}

#: ssl module protocol constants worth flagging (below TLS 1.2)
_SSL_PROTOCOL_ATTRS = {
    "ssl.PROTOCOL_SSLv2": "SSL-3.0",
    "ssl.PROTOCOL_SSLv3": "SSL-3.0",
    "ssl.PROTOCOL_TLSv1": "TLS-1.0",
    "ssl.PROTOCOL_TLSv1_1": "TLS-1.1",
    "ssl.TLSVersion.SSLv3": "SSL-3.0",
    "ssl.TLSVersion.TLSv1": "TLS-1.0",
    "ssl.TLSVersion.TLSv1_1": "TLS-1.1",
}

#: weak tokens inside OpenSSL cipher-suite strings (ssl.set_ciphers)
_CIPHER_SUITE_TOKENS = {
    "RC4": "RC4",
    "3DES": "3DES",
    "DES-CBC3": "3DES",
    "DES": "DES",
    "MD5": "MD5",
    "NULL": None,  # matched but has no algorithm entry; skipped
}


class PythonDetector(Detector):
    """AST-based detector for Python source files."""

    name = "python"

    def applies_to(self, path: PurePath) -> bool:
        return path.suffix in (".py", ".pyw")

    def detect(self, path: PurePath, content: str) -> Iterable[CryptoAsset]:
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError):
            yield from regex_fallback_scan(path, content, self.name)
            return
        yield from _Scanner(path, content).scan(tree)


class _Scanner:
    """Single-file scan state: alias map, key-size inference, consumed nodes."""

    def __init__(self, path: PurePath, content: str) -> None:
        self.path = path
        self.lines = content.splitlines()
        self.aliases: dict[str, str] = {}
        self.key_bits: dict[str, int] = {}  # variable name -> inferred key bits
        self.consumed: set[int] = set()  # id() of Call nodes already folded in
        self.seen: set[tuple[int, str, str | None]] = set()

    # -- name resolution ----------------------------------------------------

    def _collect_imports(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.aliases[a.asname or a.name.split(".")[0]] = (
                        a.name if a.asname else a.name.split(".")[0]
                    )
                    if a.asname:
                        self.aliases[a.asname] = a.name
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for a in node.names:
                    self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"

    def _resolve(self, node: ast.expr) -> str:
        """Resolve a Name/Attribute chain to a full dotted path via the alias map."""
        parts: list[str] = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            base = self.aliases.get(cur.id, cur.id)
            parts.append(base)
        else:
            return ""
        return ".".join(reversed(parts))

    # -- key-size inference (simple, module-local) ---------------------------

    def _infer_bits(self, node: ast.expr) -> int | None:
        """Best-effort key size in bits for an expression, else None."""
        if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
            return len(node.value) * 8
        if isinstance(node, ast.Name):
            return self.key_bits.get(node.id)
        if isinstance(node, ast.Call):
            dotted = self._resolve(node.func)
            if dotted == "os.urandom" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                    return arg.value * 8
            if dotted.endswith(".generate_key"):
                for kw in node.keywords:
                    if kw.arg == "bit_length" and isinstance(kw.value, ast.Constant):
                        return int(kw.value.value)
                if "ChaCha20Poly1305" in dotted:
                    return 256
        return None

    def _collect_assignments(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name):
                    bits = self._infer_bits(node.value)
                    if bits is not None:
                        self.key_bits[target.id] = bits

    # -- asset emission -------------------------------------------------------

    def _emit(
        self,
        node: ast.AST,
        algorithm: str,
        *,
        confidence: Confidence = Confidence.HIGH,
        key_size: int | None = None,
        curve: str | None = None,
        mode: str | None = None,
        usage_family: Family | None = None,
        note: str = "",
    ) -> Iterator[CryptoAsset]:
        line = getattr(node, "lineno", 1)
        key = (line, algorithm, mode)
        if key in self.seen:
            return
        self.seen.add(key)
        yield CryptoAsset(
            algorithm=algorithm,
            file_path=str(self.path),
            line_number=line,
            detector="python",
            confidence=confidence,
            snippet=make_snippet(self.lines, line),
            key_size=key_size,
            curve=curve,
            mode=mode,
            usage_family=usage_family,
            note=note,
        )

    @staticmethod
    def _aes_name(bits: int | None) -> tuple[str, str]:
        """(canonical AES name, note) for an inferred key size."""
        if bits in (128, 192, 256):
            return f"AES-{bits}", ""
        return "AES", "key size not determined from call site"

    # -- the scan -------------------------------------------------------------

    def scan(self, tree: ast.AST) -> Iterator[CryptoAsset]:
        self._collect_imports(tree)
        self._collect_assignments(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and id(node) not in self.consumed:
                yield from self._scan_call(node)
            elif isinstance(node, ast.Attribute):
                yield from self._scan_attribute(node)

    def _scan_attribute(self, node: ast.Attribute) -> Iterator[CryptoAsset]:
        dotted = self._resolve(node)
        protocol = _SSL_PROTOCOL_ATTRS.get(dotted)
        if protocol:
            yield from self._emit(node, protocol, usage_family=Family.PROTOCOL)

    def _scan_call(self, node: ast.Call) -> Iterator[CryptoAsset]:  # noqa: C901
        dotted = self._resolve(node.func)
        if not dotted:
            return

        # ---- stdlib: hashlib / hmac / ssl ----
        if dotted.startswith("hashlib."):
            func = dotted.removeprefix("hashlib.")
            if func in _HASHLIB_FUNCS:
                yield from self._emit(node, _HASHLIB_FUNCS[func])
            elif func == "new" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    name = arg.value.lower().replace("-", "_")
                    algorithm = _HASHLIB_FUNCS.get(name)
                    if algorithm:
                        yield from self._emit(node, algorithm)
            elif func == "pbkdf2_hmac":
                yield from self._emit(node, "PBKDF2")
            elif func == "scrypt":
                yield from self._emit(node, "SCRYPT")
            return
        if dotted in ("hmac.new", "hmac.digest"):
            yield from self._emit(node, "HMAC")
            return
        if dotted == "ssl.set_ciphers" or dotted.endswith(".set_ciphers"):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(
                node.args[0].value, str
            ):
                yield from self._scan_cipher_suite_string(node, node.args[0].value)
            return

        # ---- pyca cryptography: asymmetric key generation ----
        if ".asymmetric." in dotted or dotted.startswith(("rsa.", "dsa.", "ec.")):
            yield from self._scan_pyca_asymmetric(node, dotted)
            return

        # ---- pyca cryptography: Cipher(algorithms.X, modes.Y) ----
        if dotted.endswith(".Cipher") and ".ciphers" in dotted:
            yield from self._scan_pyca_cipher(node)
            return
        if ".ciphers.algorithms." in dotted:
            yield from self._scan_pyca_algorithm(node, dotted, mode=None)
            return

        # ---- pyca cryptography: AEAD classes ----
        if ".aead." in dotted:
            yield from self._scan_pyca_aead(node, dotted)
            return

        # ---- pyca cryptography: KDFs ----
        if dotted.endswith(".PBKDF2HMAC"):
            yield from self._emit(node, "PBKDF2")
            return
        if dotted.endswith((".Scrypt", ".kdf.scrypt.Scrypt")):
            yield from self._emit(node, "SCRYPT")
            return

        # ---- third-party password hashing ----
        if dotted.startswith("argon2.") or dotted.endswith("argon2.PasswordHasher"):
            yield from self._emit(node, "ARGON2")
            return
        if dotted in ("bcrypt.hashpw", "bcrypt.gensalt", "bcrypt.checkpw", "bcrypt.kdf"):
            yield from self._emit(node, "BCRYPT")
            return

        # ---- PyCryptodome ----
        if dotted.startswith(("Crypto.", "Cryptodome.")):
            yield from self._scan_pycryptodome(node, dotted)
            return

    def _scan_pyca_asymmetric(self, node: ast.Call, dotted: str) -> Iterator[CryptoAsset]:
        if "ed25519" in dotted or "ed448" in dotted:
            if dotted.endswith(".generate") or dotted.endswith(".from_private_bytes"):
                yield from self._emit(node, "EDDSA")
            return
        if "x25519" in dotted or "x448" in dotted:
            if dotted.endswith(".generate") or dotted.endswith(".from_private_bytes"):
                yield from self._emit(node, "ECDH")
            return
        if dotted.endswith("rsa.generate_private_key"):
            key_size = None
            for kw in node.keywords:
                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                    key_size = int(kw.value.value)
            yield from self._emit(node, "RSA", key_size=key_size)
            return
        if dotted.endswith("dsa.generate_private_key"):
            yield from self._emit(node, "DSA")
            return
        if dotted.endswith("ec.generate_private_key"):
            curve = None
            curve_arg: ast.expr | None = node.args[0] if node.args else None
            for kw in node.keywords:
                if kw.arg == "curve":
                    curve_arg = kw.value
            if curve_arg is not None:
                inner = curve_arg.func if isinstance(curve_arg, ast.Call) else curve_arg
                curve_dotted = self._resolve(inner)
                if curve_dotted:
                    curve = curve_dotted.rsplit(".", 1)[-1]
                if isinstance(curve_arg, ast.Call):
                    self.consumed.add(id(curve_arg))
            yield from self._emit(node, "ECDSA", curve=curve)
            return
        if dotted.endswith(".ECDH"):
            yield from self._emit(node, "ECDH")
            return
        if dotted.endswith("dh.generate_parameters") or dotted.endswith(
            "dh.generate_private_key"
        ):
            yield from self._emit(node, "DH")
            return

    def _scan_pyca_cipher(self, node: ast.Call) -> Iterator[CryptoAsset]:
        algorithm_arg = node.args[0] if node.args else None
        mode_arg = node.args[1] if len(node.args) > 1 else None
        for kw in node.keywords:
            if kw.arg == "algorithm":
                algorithm_arg = kw.value
            elif kw.arg == "mode":
                mode_arg = kw.value
        mode = None
        if mode_arg is not None:
            mode_inner = mode_arg.func if isinstance(mode_arg, ast.Call) else mode_arg
            mode_dotted = self._resolve(mode_inner)
            if mode_dotted:
                mode = mode_dotted.rsplit(".", 1)[-1].upper()
            if isinstance(mode_arg, ast.Call):
                self.consumed.add(id(mode_arg))
        if isinstance(algorithm_arg, ast.Call):
            self.consumed.add(id(algorithm_arg))
            algo_dotted = self._resolve(algorithm_arg.func)
            yield from self._scan_pyca_algorithm(algorithm_arg, algo_dotted, mode=mode)

    def _scan_pyca_algorithm(
        self, node: ast.Call, dotted: str, mode: str | None
    ) -> Iterator[CryptoAsset]:
        cls = dotted.rsplit(".", 1)[-1]
        if cls in ("AES", "AES128", "AES256"):
            if cls == "AES128":
                name, note = "AES-128", ""
            elif cls == "AES256":
                name, note = "AES-256", ""
            else:
                bits = self._infer_bits(node.args[0]) if node.args else None
                name, note = self._aes_name(bits)
            key_size = int(name.split("-")[1]) if "-" in name else None
            yield from self._emit(node, name, key_size=key_size, mode=mode, note=note)
        elif cls == "TripleDES":
            yield from self._emit(node, "3DES", mode=mode)
        elif cls == "Blowfish":
            yield from self._emit(node, "BLOWFISH", mode=mode)
        elif cls in ("ARC4", "RC4"):
            yield from self._emit(node, "RC4", mode=mode)
        elif cls == "ChaCha20":
            yield from self._emit(node, "CHACHA20", key_size=256, mode=mode)

    def _scan_pyca_aead(self, node: ast.Call, dotted: str) -> Iterator[CryptoAsset]:
        if dotted.endswith(".generate_key"):
            return  # key generation is folded into the constructor via inference
        cls = dotted.rsplit(".", 1)[-1]
        if cls in ("AESGCM", "AESGCMSIV", "AESCCM", "AESOCB3", "AESSIV"):
            mode = {"AESGCM": "GCM", "AESGCMSIV": "GCM-SIV", "AESCCM": "CCM",
                    "AESOCB3": "OCB3", "AESSIV": "SIV"}[cls]
            bits = self._infer_bits(node.args[0]) if node.args else None
            name, note = self._aes_name(bits)
            key_size = bits if bits in (128, 192, 256) else None
            yield from self._emit(node, name, key_size=key_size, mode=mode, note=note)
        elif cls == "ChaCha20Poly1305":
            yield from self._emit(node, "CHACHA20", key_size=256)

    def _scan_pycryptodome(self, node: ast.Call, dotted: str) -> Iterator[CryptoAsset]:
        parts = dotted.split(".")
        if len(parts) < 3:
            return
        _, section, module = parts[0], parts[1], parts[2]
        tail = parts[-1]
        if section == "Cipher" and module in _PYCRYPTODOME_CIPHERS and tail == "new":
            algorithm, fixed_bits = _PYCRYPTODOME_CIPHERS[module]
            mode = None
            for arg in node.args[1:2]:
                mode_dotted = self._resolve(arg)
                mode_name = mode_dotted.rsplit(".", 1)[-1]
                if mode_name.startswith("MODE_"):
                    mode = mode_name.removeprefix("MODE_")
            bits = fixed_bits
            if algorithm == "AES":
                bits = self._infer_bits(node.args[0]) if node.args else None
                algorithm, note = self._aes_name(bits)
                key_size = bits if bits in (128, 192, 256) else None
                yield from self._emit(node, algorithm, key_size=key_size, mode=mode, note=note)
                return
            yield from self._emit(node, algorithm, key_size=bits, mode=mode)
        elif section == "Hash" and module in _PYCRYPTODOME_HASHES and tail == "new":
            yield from self._emit(node, _PYCRYPTODOME_HASHES[module])
        elif section == "PublicKey" and tail in ("generate", "construct", "import_key"):
            if module == "RSA":
                key_size = None
                if tail == "generate" and node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                        key_size = arg.value
                yield from self._emit(node, "RSA", key_size=key_size)
            elif module == "DSA":
                yield from self._emit(node, "DSA")
            elif module == "ECC":
                curve = None
                for kw in node.keywords:
                    if kw.arg == "curve" and isinstance(kw.value, ast.Constant):
                        curve = str(kw.value.value)
                yield from self._emit(node, "ECDSA", curve=curve)
        elif section == "Protocol" and module == "KDF":
            if tail == "PBKDF2":
                yield from self._emit(node, "PBKDF2")
            elif tail == "scrypt":
                yield from self._emit(node, "SCRYPT")
            elif tail == "bcrypt":
                yield from self._emit(node, "BCRYPT")

    def _scan_cipher_suite_string(self, node: ast.Call, value: str) -> Iterator[CryptoAsset]:
        """Weak tokens in an OpenSSL cipher-suite string (MEDIUM: string config)."""
        upper = value.upper()
        for token, algorithm in _CIPHER_SUITE_TOKENS.items():
            if algorithm and token in upper and f"!{token}" not in upper:
                # "DES" would also match inside "3DES"/"DES-CBC3"; require exact-ish hit
                if token == "DES" and ("3DES" in upper or "DES-CBC3" in upper):
                    continue
                yield from self._emit(
                    node,
                    algorithm,
                    confidence=Confidence.MEDIUM,
                    note=f"cipher-suite string contains {token}",
                )
