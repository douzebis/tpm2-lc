// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"main/src/lib"
)

// === Read an x509 private key from disk ======================================

func ReadPublicKey(
	publicKeyPath string,
) interface{} {
	publicKeyPEM, err := ioutil.ReadFile(fmt.Sprintf("%s.pub", publicKeyPath))
	if err != nil {
		lib.Fatal("ioutil.ReadFile() failed: %v", err)
	}

	publicKeyBlock, _ := pem.Decode(publicKeyPEM)

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		lib.Fatal("x509.ParsePKIXPublicKey() failed: %v", err)
	}

	return publicKey
}
