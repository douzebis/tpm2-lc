// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"

	"github.com/golang/glog"

	"main/src/certs"
)

// ### Clear TPM (on Attestor) #################################################

func VerifyEKPub(ekPublicKey *rsa.PublicKey, ekPubBytes []byte) {

	// === Verify TPM EK Pub with TPM manufacturer =============================

	// --- Read TPM Manufacturer CA cert ---------------------------------------

	tpmCaPem, err := ioutil.ReadFile("TPM-CA/tpm-ca.crt")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed: %v", err)
	}
	//glog.V(0).Infof("TPM-CA/tpm-ca.crt:\n%s", string(tpmCaPem))

	tpmCaBlock, _ := pem.Decode(tpmCaPem)
	tpmCaCert, err := x509.ParseCertificate(tpmCaBlock.Bytes)
	if err != nil {
		glog.Fatalf("x509.ParseCertificate() failed: %v", err)
	}

	// --- Check TPM Manufacturer CA cert --------------------------------------

	tpmRoots := x509.NewCertPool()
	tpmRoots.AddCert(tpmCaCert)
	tpmOpts := x509.VerifyOptions{
		Roots: tpmRoots,
	}

	if _, err := tpmCaCert.Verify(tpmOpts); err != nil {
		glog.Fatalf("tpmCaCert.Verify() failed: %v", err)
	} else {
		glog.V(0).Infof("Verified %s", "TPM-CA/tpm-ca.crt")
	}

	// --- Read TPM cert -------------------------------------------------------

	tpmPem, err := ioutil.ReadFile("TPM-CA/tpm.crt")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed: %v", err)
	}
	//glog.V(0).Infof("TPM-CA/tpm.crt:\n%s", string(tpmPem))

	tpmBlock, _ := pem.Decode(tpmPem)
	tpmCert, err := x509.ParseCertificate(tpmBlock.Bytes)
	if err != nil {
		glog.Fatalf("x509.ParseCertificate() failed: %v", err)
	}

	// --- Check TPM cert ------------------------------------------------------

	unhandledCriticalExtensions := tpmCert.UnhandledCriticalExtensions
	glog.V(0).Infof("uce %v", unhandledCriticalExtensions)

	tpmCert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}

	if _, err := tpmCert.Verify(tpmOpts); err != nil {
		glog.Fatalf("tpmCert.Verify() failed: %v", err)
	} else {
		glog.V(0).Infof("Verified %s", "TPM-CA/tpm.crt")
	}

	// --- Check SAN in TPM cert -----------------------------------------------

	subjectAltName := asn1.ObjectIdentifier{2, 5, 29, 17}

	if len(unhandledCriticalExtensions) != 1 {
		glog.Fatalf("Unexpected UnhandledCriticalExtensions: %v",
			unhandledCriticalExtensions)
	}
	if !unhandledCriticalExtensions[0].Equal(subjectAltName) {
		glog.Fatalf("OID is not SAN: %v", unhandledCriticalExtensions[0])
	}

	expectedSAN := pkix.Extension(
		*certs.CreateSubjectAltName(
			[]byte("id: Google"),
			[]byte("id: Shielded VM vTPM"),
			[]byte("id: 00010001"),
		),
	)

	for _, ext := range tpmCert.Extensions {
		if ext.Id.Equal(subjectAltName) {
			if !ext.Critical {
				glog.Fatalf("SAN should be critical")
			}
			if !ext.Id.Equal(expectedSAN.Id) || !bytes.Equal(ext.Value, expectedSAN.Value) {
				glog.Fatalf("SAN has unexpected value: %v", ext)

			}
		}
	}

	// --- Check TPM EK Pub matches TPM cert -----------------------------------

	certPubBytes, err := x509.MarshalPKIXPublicKey(tpmCert.PublicKey)
	if err != nil {
		glog.Fatalf("x509.MarshalPKIXPublicKey() failed: %v", err)
	}

	if !bytes.Equal(ekPubBytes, certPubBytes) {
		glog.Fatalf("EK Pub does not match TPM certificate")
	}
	glog.V(0).Infof("EK Pub matches TPM certificate")

	ekPubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekPubBytes,
		},
	)

	err = ioutil.WriteFile("Verifier/ek.pub", ekPubPem, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed for EK Pub: %v", err)
	}
	glog.V(0).Infof("Wrote Verifier/ek.pub")
}
