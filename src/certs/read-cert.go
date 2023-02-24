// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"crypto/x509"
	"encoding/asn1"
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

// === Verify an x509 certificate ==============================================

func VerifyCert(
	cert x509.Certificate,
	parent x509.Certificate,
) {
	// Note: equivalently with openssl:
	// openssl verify -CAfile TPM-CA/tpm-ca.crt TPM-CA/tpm.crt
	// openssl x509 -noout -ext subjectAltName -in TPM-CA/tpm.crt

	// Remove SAN (2.5.29.17) from unhandled critical extensions
	uhce := []asn1.ObjectIdentifier{}
	for _, ext := range cert.UnhandledCriticalExtensions {
		lib.Comment("extension %s", ext.String())
		if !ext.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			uhce = append(uhce, ext)
		}
	}
	cert.UnhandledCriticalExtensions = uhce

	tpmRoots := x509.NewCertPool()
	tpmRoots.AddCert(&parent)
	tpmOpts := x509.VerifyOptions{
		Roots: tpmRoots,
	}

	if _, err := cert.Verify(tpmOpts); err != nil {
		lib.Fatal("cert.Verify() failed: %v", err)
	}
}
