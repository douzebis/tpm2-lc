// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"main/src/lib"
)

// === Create TPM EK certificate ===============================================

func CreateEKCert(
	// See https://upgrades.intel.com/content/CRL/ekcert/EKcertPolicyStatement.pdf
	// See https://marc.info/?l=openssl-users&m=135119943225986&w=2
	publicKeyPath string,
	manufacturerID string,
	modelName string,
	version string,
	caCertPath string,
	certPath string,
) {
	// Retrieve EK public key
	publicKey := ReadPublicKey(publicKeyPath)

	// Retrieve ca certificate
	caCert := ReadCert(fmt.Sprintf("%s.crt", caCertPath))

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
				[]byte(manufacturerID), // "id: Google"
				[]byte(modelName),      // "id: Shielded VM vTPM"
				[]byte(version),        // "id: 00010001"
			),
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		&certTemplate,
		&caCert,
		publicKey,
		caKey)
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

	// Note: equivalently with openssl:
	// openssl verify -CAfile TPM-CA/tpm-ca.crt TPM-CA/tpm.crt
	// openssl x509 -noout -ext subjectAltName -in TPM-CA/tpm.crt

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		lib.Fatal("x509.ParseCertificate() failed: %v", err)
	}
	cert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}

	roots := x509.NewCertPool()
	roots.AddCert(&caCert)
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		lib.Fatal("tpmCert.Verify() failed: %v", err)
	} else {
		lib.Print("Verified %s", "TPM-CA/tpm.crt")
	}

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
