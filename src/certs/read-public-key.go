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

func ReadPublicKey(
	publicKeyPath string,
) rsa.PublicKey {

	publicKeyPEM := lib.Read(fmt.Sprintf("%s.pub", publicKeyPath))

	publicKeyBlock, _ := pem.Decode(publicKeyPEM)
	if publicKeyBlock == nil {
		lib.Fatal("pem.Decode() failed")
	}
	if publicKeyBlock.Type != "RSA" {
		lib.Fatal("Block is not of type RSA: %v", publicKeyBlock.Type)
	}

	pubKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		lib.Fatal("x509.ParsePKIXPublicKey() failed: %v", err)
	}

	// Retrieve EK Pub as *rsa.PublicKey
	// See https://stackoverflow.com/a/44317246
	switch ekPubTyp := pubKey.(type) {
	case *rsa.PublicKey:
	default:
		lib.Fatal("ekPublicKey is not of type RSA: %v", ekPubTyp)
	}
	publicKey, _ := pubKey.(*rsa.PublicKey)
	lib.Verbose("publicKey %v", publicKey)

	return *publicKey
}
