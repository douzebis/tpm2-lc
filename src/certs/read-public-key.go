// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"main/src/lib"
)

// === Read an x509 private key from disk ======================================

func ReadPublicKey(
	publicKeyPath string,
) rsa.PublicKey {
	publicKeyPEM, err := ioutil.ReadFile(fmt.Sprintf("%s.pub", publicKeyPath))
	if err != nil {
		lib.Fatal("ioutil.ReadFile() failed: %v", err)
	}

	publicKeyBlock, _ := pem.Decode(publicKeyPEM)

	pubKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		lib.Fatal("x509.ParsePKIXPublicKey() failed: %v", err)
	}

	// Retrieve EK Pub as *rsa.PublicKey
	// See https://stackoverflow.com/a/44317246
	switch ekPubTyp := pubKey.(type) {
	case *rsa.PublicKey:
		lib.Comment("ekPublicKey is of type RSA")
	default:
		lib.Fatal("ekPublicKey is not of type RSA: %v", ekPubTyp)
	}
	publicKey, _ := pubKey.(*rsa.PublicKey)
	lib.Comment("publicKey %v", publicKey)

	return *publicKey
}
