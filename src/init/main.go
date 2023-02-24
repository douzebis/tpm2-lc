// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"

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

	// Create certificate for Manufacturer CA
	certs.CreateCACert(
		"Manufacturer",
		"Manufacturer/manufacturer-ca",
	)

	// Create certificate for Owner CA
	//manufacturerCert, manufacturerPrivKey :=
	certs.CreateCACert(
		"Owner",
		"Owner/owner-ca",
	)

	// Open TPM
	rwc := tpm.OpenFlush(*tpmPath, *flush)
	defer rwc.Close()

	// In this mock-up, we fake boot image PCRs prediction by simply
	// reading current machine PCRs status

	// Read and save TPM PCRs values
	tpm.ReadPCRs(
		rwc,
		[]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 14}, // Used for boot measurement
		"CICD/pcrs",
	)

	// Read and save TPM EK Pub
	//ekPublicKey, ekPubBytes :=
	steps.GetEKPub(
		rwc,
		"Manufacturer/ek",
	)

	// Create TPM EK Cert
	certs.CreateEKCert(
		"Manufacturer/ek",
		"id: Google",
		"Shielded VM vTPM",
		"id: 00010001",
		"Manufacturer/manufacturer-ca",
		"Manufacturer/ek",
	)
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
