// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"main/src/lib"
)

// === Read an x509 certificate from disk

func ReadCert(
	pathPrefix string,
) x509.Certificate {
	certPEM, err := ioutil.ReadFile(fmt.Sprintf("%s.crt", pathPrefix))
	if err != nil {
		lib.Fatal("ioutil.ReadFile() failed: %v", err)
	}
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		lib.Fatal("pem.Decode() failed: %v", err)
	}
	if certBlock.Type != "CERTIFICATE" {
		lib.Fatal("Cert type != CERTIFICATE")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		lib.Fatal("x509.ParseCertificate() failed: %v", err)
	}

	return *cert
}
