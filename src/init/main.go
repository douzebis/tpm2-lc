// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"

	"main/src/certs"
	"main/src/lib"
	"main/src/steps"
	"main/src/tpm"

	"github.com/google/go-tpm-tools/client"
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

	// In this mock-up, we fake boot image PCRs prediction by simply
	// reading current machine PCRs status

	// Read and save TPM PCRs values
	lib.PRINT("=== INIT: RETRIEVE TPM PLATFORM CONFIGURATION REGISTERS ========================")
	tpm.ReadPCRs(
		rwc,
		[]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 14}, // Used for boot measurement
		"CICD/pcrs",
	)

	// Read and save TPM PCRs values
	lib.PRINT("=== INIT: RETRIEVE EVENT LOG ===================================================")
	eventLog, err := client.GetEventLog(rwc)
	if err != nil {
		lib.Fatal("client.GetEventLog(): %v", err)
	}
	lib.Write("CICD/event-log.bin", eventLog, 0644)

	return

	// Create certificate for Manufacturer CA
	lib.PRINT("=== INIT: CREATE MANUFACTURER CA CERT ==========================================")
	certs.CreateCACert(
		"Manufacturer",
		"Manufacturer/manufacturer-ca",
	)

	// Create certificate for Owner CA
	lib.PRINT("=== INIT: CREATE OWNER CA CERT =================================================")
	certs.CreateCACert(
		"Owner",
		"Owner/owner-ca",
	)

	// Open TPM
	rwc = tpm.OpenFlush(*tpmPath, *flush)
	defer rwc.Close()

	// Read and save TPM EK Pub
	steps.GetEKPub(
		rwc,
		"Manufacturer/ek",
	)

	// Create TPM EK Cert
	lib.PRINT("=== INIT: CREATE EK CERT =======================================================")
	certs.CreateEKCert(
		"Manufacturer/ek",
		"id: Google",
		"Shielded VM vTPM",
		"id: 00010001",
		"Manufacturer/manufacturer-ca",
		"Manufacturer/ek",
	)

	// In this mock-up, we fake boot image PCRs prediction by simply
	// reading current machine PCRs status

	// Read and save TPM PCRs values
	lib.PRINT("=== INIT: RETRIEVE TPM PLATFORM CONFIGURATION REGISTERS ========================")
	tpm.ReadPCRs(
		rwc,
		[]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 14}, // Used for boot measurement
		"CICD/pcrs",
	)

	// Read and save TPM PCRs values
	lib.PRINT("=== INIT: RETRIEVE EVENT LOG ===================================================")
	eventLog, err := client.GetEventLog(rwc)
	if err != nil {
		lib.Fatal("client.GetEventLog(): %v", err)
	}
	lib.Write("CICD/event-log.bin", eventLog, 0644)
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
