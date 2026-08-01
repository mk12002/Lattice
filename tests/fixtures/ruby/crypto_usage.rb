# Fixture: Ruby crypto across the risk spectrum.
#
# Known answers (all medium confidence; identifiers below are the real call
# sites — the header intentionally avoids matchable tokens):
# - the MD5 digest              -> MD5, P0 classically broken
# - the aes-128-ecb cipher      -> AES-128 + ECB, P0 broken usage
# - the RSA key (2048)          -> RSA 2048, P0 quantum-broken + HNDL
# - the aes-256-gcm cipher      -> AES-256 + GCM, compliant

require 'openssl'

def weak_digest(data)
  OpenSSL::Digest::MD5.new.digest(data)          # KNOWN: MD5, P0
end

def legacy_cipher
  OpenSSL::Cipher.new('aes-128-ecb')             # KNOWN: AES-128 + ECB, P0
end

def quantum_vulnerable
  OpenSSL::PKey::RSA.new(2048)                    # KNOWN: RSA 2048, P0
end

def modern_seal
  OpenSSL::Cipher.new('aes-256-gcm')             # KNOWN: AES-256 + GCM, compliant
end
