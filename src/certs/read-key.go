// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"main/src/lib"
)

// === Read an x509 private key from disk ======================================

func ReadKey(
	pathPrefix string,
) rsa.PrivateKey {

	keyPEM := lib.Read(fmt.Sprintf("%s.key", pathPrefix))

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		lib.Fatal("pem.Decode() failed")
	}
	if keyBlock.Type != "RSA PRIVATE KEY" {
		lib.Fatal("Block is not of type RSA PRIVATE KEY: %v", keyBlock.Type)
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		lib.Fatal("x509.ParsePKCS1PrivateKey() failed: %v", err)
	}

	return *key
}
