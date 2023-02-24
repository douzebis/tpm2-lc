// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/golang/glog"
)

// ### CreateAKCert (on Verifier and Owner-CA) #################################

func CreateAKCert() {

	referenceSecret, err := ioutil.ReadFile("Verifier/secret")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed: %v", err)
	}

	returnedSecret, err := ioutil.ReadFile("Attestor/secret")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed: %v", err)
	}

	if !bytes.Equal(referenceSecret, returnedSecret) {
		glog.Fatalf("Secrets do not match, aborting onboarding")
	}
	glog.V(0).Infof("Secrets match, creating AK cert")

	// === Retrieve Owner CA key and certificate ===============================

	// --- Read Owner CA cert --------------------------------------------------

	ownerCaPem, err := ioutil.ReadFile("Owner-CA/owner-ca.crt")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed: %v", err)
	}

	ownerCaBlock, _ := pem.Decode(ownerCaPem)
	ownerCaCert, err := x509.ParseCertificate(ownerCaBlock.Bytes)
	if err != nil {
		glog.Fatalf("x509.ParseCertificate() failed: %v", err)
	}

	// --- Check Owner CA cert -------------------------------------------------

	ownerRoots := x509.NewCertPool()
	ownerRoots.AddCert(ownerCaCert)
	ownerOpts := x509.VerifyOptions{
		Roots: ownerRoots,
	}

	if _, err := ownerCaCert.Verify(ownerOpts); err != nil {
		glog.Fatalf("ownerCaCert.Verify() failed: %v", err)
	} else {
		glog.V(0).Infof("Verified %s", "Owner-CA/owner-ca.crt")
	}

	// --- Read Owner CA key ---------------------------------------------------

	ownerCaPrivKeyPem, err := ioutil.ReadFile("Owner-CA/owner-ca.key")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed: %v", err)
	}

	ownerCaPrivKeyBlock, _ := pem.Decode(ownerCaPrivKeyPem)
	ownerCaPrivKey, err := x509.ParsePKCS1PrivateKey(ownerCaPrivKeyBlock.Bytes)
	if err != nil {
		glog.Fatalf("x509.ParsePKCS1PrivateKey() failed: %v", err)
	}

	// == Create AK certificate ================================================

	// --- Retrieve AK Pub -----------------------------------------------------

	akPublicKeyPEM, err := ioutil.ReadFile("Attestor/ak.pub")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for Attestor/ak.pub: %v", err)
	}

	akPublicKeyBlock, _ := pem.Decode(akPublicKeyPEM)
	akPublicKeyDER, err := x509.ParsePKIXPublicKey(akPublicKeyBlock.Bytes)
	if err != nil {
		glog.Fatalf("x509.ParsePKCS1PrivateKey() failed: %v", err)
	}

	// --- Create AK certificate -----------------------------------------------

	akTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Owner Inc"},
			CommonName:   "AK",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	akBytes, err := x509.CreateCertificate(
		rand.Reader,
		&akTemplate,
		ownerCaCert,
		akPublicKeyDER,
		ownerCaPrivKey)
	if err != nil {
		glog.Fatalf("x509.CreateCertificate() failed: %v", err)
	}

	// pem encode
	akPEM := []byte(pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: akBytes,
		},
	))

	err = ioutil.WriteFile("Owner-CA/ak.crt", akPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed for Owner-CA/ak.crt: %v", err)
	}
	glog.V(0).Infof("Wrote Owner-CA/ak.crt")

	// --- Verify TPM cert -----------------------------------------------------

	// Note: equivalently with openssl:
	// openssl verify -CAfile TPM-CA/tpm-ca.crt TPM-CA/tpm.crt
	// openssl x509 -noout -ext subjectAltName -in TPM-CA/tpm.crt

	akOwnerCert, err := x509.ParseCertificate(akBytes)
	if err != nil {
		glog.Fatalf("x509.ParseCertificate() failed: %v", err)
	}
	//akOwnerCert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}
	if _, err := akOwnerCert.Verify(ownerOpts); err != nil {
		glog.Fatalf("akOwnerCert.Verify() failed: %v", err)
	} else {
		glog.V(0).Infof("Verified %s", "Owner-CA/ak.crt")
	}
}
