// Fixture: Go crypto imports across the risk spectrum.
//
// Known answers (all high confidence — Go rejects unused imports):
// - crypto/md5                              -> MD5, P0 classically broken
// - crypto/rsa                              -> RSA, P0 quantum-broken + HNDL
// - crypto/sha256                           -> SHA-256, P3
// - golang.org/x/crypto/chacha20poly1305    -> CHACHA20, compliant
package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	sum := md5.Sum([]byte("legacy checksum"))
	fmt.Printf("%x\n", sum)

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = key

	digest := sha256.Sum256([]byte("payload"))
	_ = digest

	aead, _ := chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
	_ = aead
}
