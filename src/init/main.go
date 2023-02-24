// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"

	"main/src/certs"
	"main/src/steps"
	"main/src/tpm"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	flush   = flag.String("flush", "all", "Flush contexts, must be oneof transient|saved|loaded|all")
)

func main() {
	flag.Parse()

	// Open TPM
	rwc := tpm.OpenFlush(*tpmPath, *flush)
	defer rwc.Close()

	// Read and save TPM PCRs values
	tpm.ReadPCRs(
		rwc,
		[]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 14}, // Used for boot measurement
		"CI-CD/pcrs",
	)

	// Read and save TPM EK Pub
	ekPublicKey, ekPubBytes := steps.GetEKPub(
		rwc,
		"TPM-CA/ek",
	)

	// Create certificate for TPM CA
	tpmCaCert, tpmCaPrivKey := certs.CreateCA(
		"TPM Manufacturer",
		"TPM-CA/tpm-ca",
	)

	return

	// === Create certificate for TPM ==========================================

	// --- Retrieve TPM EK Pub -------------------------------------------------

	ekTpmKey, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		glog.Fatalf("Unable to load SRK from TPM: %v", err)
	}

	ekTpmPubKey, _, _, err := tpm2.ReadPublic(rwc, ekTpmKey.Handle())
	if err != nil {
		glog.Fatalf("tpm2.ReadPublic() failed: %s", err)
	}

	ekPubKey, err := ekTpmPubKey.Key()
	if err != nil {
		glog.Fatalf("ekPublicKey.Key() failed: %s", err)
	}
	ekPubBytes, err = x509.MarshalPKIXPublicKey(ekPubKey)
	if err != nil {
		glog.Fatalf("x509.MarshalPKIXPublicKey() failed: %v", err)
	}

	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekPubBytes,
		},
	)

	err = ioutil.WriteFile("TPM-CA/ek.pem", ekPubPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}

	glog.V(0).Infof("Wrote TPM-CA/ek.pem")

	switch ekPubKey.(type) {
	case *rsa.PublicKey:
		glog.V(0).Infof("ekPublicKey is of type RSA")
	}
	// From https://stackoverflow.com/a/44317246
	ekPublicKey, _ = ekPubKey.(*rsa.PublicKey)

	// --- Create TPM EK certificate -------------------------------------------

	tpmTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"TPM Inc"},
			CommonName:   "TPM",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		KeyUsage:  x509.KeyUsageKeyEncipherment,
		ExtraExtensions: []pkix.Extension{
			*certs.CreateSubjectAltName(
				[]byte("id: Google"),
				[]byte("id: Shielded VM vTPM"),
				[]byte("id: 00010001"),
			),
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	tpmBytes, err := x509.CreateCertificate(
		rand.Reader,
		&tpmTemplate,
		tpmCaCert,
		ekPublicKey,
		tpmCaPrivKey)
	if err != nil {
		glog.Fatalf("x509.CreateCertificate() failed: %v", err)
	}

	// pem encode
	tpmPEM := []byte(pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: tpmBytes,
		},
	))

	err = ioutil.WriteFile("TPM-CA/tpm.crt", tpmPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}

	glog.V(0).Infof("Wrote TPM-CA/tpm.crt")

	// --- Verify TPM cert -----------------------------------------------------

	// Note: equivalently with openssl:
	// openssl verify -CAfile TPM-CA/tpm-ca.crt TPM-CA/tpm.crt
	// openssl x509 -noout -ext subjectAltName -in TPM-CA/tpm.crt

	tpmCert, err := x509.ParseCertificate(tpmBytes)
	if err != nil {
		glog.Fatalf("x509.ParseCertificate() failed: %v", err)
	}
	tpmCert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}

	roots := x509.NewCertPool()
	roots.AddCert(tpmCaCert)
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := tpmCert.Verify(opts); err != nil {
		glog.Fatalf("tpmCert.Verify() failed: %v", err)
	} else {
		glog.V(0).Infof("Verified %s", "TPM-CA/tpm.crt")
	}

	// === Create certificate for Owner CA =====================================

	certs.CreateCA("TPM Owner", "Owner-CA/owner-ca")

	// === Retrieve PCRs =======================================================

	// In this tutorial, we fake boot image PCRs prediction by simply
	// reading current machine PCRs status

}

// --- Snippet: parse a certificate extensions -----------------------------

//	testPem, err := ioutil.ReadFile("TPM-CA/tpm.crt")
//	if err != nil {
//		glog.Fatalf("ioutil.ReadFile() failed: %v", err)
//	}
//	block, _ := pem.Decode([]byte(testPem))
//	if block == nil {
//		glog.Fatalf("pem.Decode() failed: %v", err)
//	}
//
//	if block.Type == "CERTIFICATE" {
//		glog.V(0).Infof("Block has type CERTIFICATE")
//		certificate, err := x509.ParseCertificate(block.Bytes)
//		if err != nil {
//			glog.Fatalf("x509.ParseCertificate() failed: %v", err)
//		}
//		for _, ext := range certificate.Extensions {
//			// filter the custom extensions by customOID
//			glog.V(0).Infof("extension %s", ext.Id.String())
//			if ext.Id.String() == "2.5.29.17" {
//				parse(ext.Value, "")
//			}
//		}
//	} else {
//		glog.V(0).Infof("Block has type %s", block.Type)
//	}

// Since GCP Shielded VMs TPM Endorsement Keys come without a proper
// certificate, we fake a TPM CA and a fake TPM EK certificate.
