// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"main/src/lib"
)

// === Verifier: create certificate =====================================

func CreateAKCert(
	publicKeyPath string,
	certName string,
	caCertPath string,
	certPath string,
) {

	lib.PRINT("=== VERIFIER: CREATE AK CERT ===================================================")

	// Retrieve AK public key
	publicKey := ReadPublicKey(publicKeyPath)

	// Retrieve CA certificate
	caCert := ReadCert(caCertPath)

	// Retrieve ca private key
	caKey := ReadKey(caCertPath)

	now := time.Now()
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: certName,
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		&certTemplate,
		&caCert,
		&publicKey,
		&caKey)
	if err != nil {
		lib.Fatal("x509.CreateCertificate() failed: %v", err)
	}

	// pem encode
	certPEM := []byte(pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		},
	))

	// Write AK Cert to disk
	lib.Write(fmt.Sprintf("%s.crt", certPath), certPEM, 0644)

	// Verify Cert
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		lib.Fatal("x509.ParseCertificate() failed: %v", err)
	}

	VerifyCert(*cert, caCert)
}
