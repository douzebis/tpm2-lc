// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"main/src/certs"
	"main/src/lib"
)

// ### Verifier: verify EK Pub #################################################

func VerifyEKPub(
	ekPublicKeyPath string,
	ekCertPath string,
	manufacturerCertPath string,
	ekVerifierPath string,
) {

	lib.PRINT("=== VERIFIER: VERIFY EK PUB ====================================================")

	// Retrieve EK public key
	ekPublicKey := certs.ReadPublicKey(ekPublicKeyPath)

	// Retrieve EK certificate
	ekCert := certs.ReadCert(ekCertPath)

	// Retrieve Manufacturer CA certificate
	manufacturerCert := certs.ReadCert(manufacturerCertPath)

	// Verify EK certificate against Manufacturer CA certificate
	certs.VerifyCert(manufacturerCert, manufacturerCert)
	certs.VerifyCert(ekCert, manufacturerCert)

	// Verify SAN in EK cert
	expectedSAN := pkix.Extension(
		*certs.CreateSubjectAltName(
			[]byte("id: Google"),
			[]byte("Shielded VM vTPM"),
			[]byte("id: 00010001"),
		),
	)
	badSAN := true
	for _, ext := range ekCert.Extensions {
		lib.Verbose("extension %s", ext.Id.String())
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			if !ext.Critical {
				lib.Fatal("SAN should be critical")
			}
			if !ext.Id.Equal(expectedSAN.Id) || !bytes.Equal(ext.Value, expectedSAN.Value) {
				lib.Fatal("SAN has unexpected value: %v", ext)
			}
			badSAN = false
		}
	}
	if badSAN {
		lib.Fatal("SAN is not properly set")
	}

	// Verify EK Pub matches EK cert
	ekPublicBytes, err := x509.MarshalPKIXPublicKey(&ekPublicKey)
	if err != nil {
		lib.Fatal("x509.MarshalPKIXPublicKey() failed: %v", err)
	}
	ekCertPublicBytes, err := x509.MarshalPKIXPublicKey(ekCert.PublicKey)
	if err != nil {
		lib.Fatal("x509.MarshalPKIXPublicKey() failed: %v", err)
	}

	if !bytes.Equal(ekPublicBytes, ekCertPublicBytes) {
		lib.Fatal("EK Pub does not match EK Cert")
	}
	lib.Print("EK Pub matches TPM certificate")

	ekPubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekPublicBytes,
		},
	)

	lib.Write(fmt.Sprintf("%s.pub", ekVerifierPath), ekPubPem, 0644)
}
