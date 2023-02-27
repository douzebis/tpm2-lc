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

// === Verifier: create TPM EK certificate =====================================

func CreateEKCert(
	// See https://upgrades.intel.com/content/CRL/ekcert/EKcertPolicyStatement.pdf
	// See https://marc.info/?l=openssl-users&m=135119943225986&w=2
	publicKeyPath string, // IN
	manufacturerID string,
	modelName string,
	version string,
	caCertPath string, // IN
	certPath string, // OUT
) {

	lib.PRINT("=== VERIFIER: CREATE EK CERT ===================================================")

	// Retrieve EK public key
	publicKey := ReadPublicKey(publicKeyPath)

	// Retrieve ca certificate
	caCert := ReadCert(caCertPath)

	// Retrieve ca private key
	caKey := ReadKey(caCertPath)

	now := time.Now()
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{},
		NotBefore:    now,
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
		ExtraExtensions: []pkix.Extension{
			*CreateSubjectAltName(
				[]byte(manufacturerID),
				[]byte(modelName),
				[]byte(version),
			),
		},
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

	lib.Write(fmt.Sprintf("%s.crt", certPath), certPEM, 0644) // "TPM-CA/tpm"

	// --- Verify TPM cert -----------------------------------------------------

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		lib.Fatal("x509.ParseCertificate() failed: %v", err)
	}

	VerifyCert(*cert, caCert)
}

// --- Snippet: parse a certificate extensions -----------------------------

//	testPem, err := ioutil.ReadFile("TPM-CA/tpm.crt")
//	if err != nil {
//		lib.Fatal("ioutil.ReadFile() failed: %v", err)
//	}
//	block, _ := pem.Decode([]byte(testPem))
//	if block == nil {
//		lib.Fatal("pem.Decode() failed: %v", err)
//	}
//
//	if block.Type == "CERTIFICATE" {
//		lib.Print("Block has type CERTIFICATE")
//		certificate, err := x509.ParseCertificate(block.Bytes)
//		if err != nil {
//			lib.Fatal("x509.ParseCertificate() failed: %v", err)
//		}
//		for _, ext := range certificate.Extensions {
//			// filter the custom extensions by customOID
//			lib.Print("extension %s", ext.Id.String())
//			if ext.Id.String() == "2.5.29.17" {
//				parse(ext.Value, "")
//			}
//		}
//	} else {
//		lib.Print("Block has type %s", block.Type)
//	}

// Since GCP Shielded VMs TPM Endorsement Keys come without a proper
// certificate, we fake a TPM CA and a fake TPM EK certificate.
