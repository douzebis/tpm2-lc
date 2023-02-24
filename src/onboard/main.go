// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"

	"main/src/steps"
	"main/src/tpm"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	flush   = flag.String("flush", "all", "Flush contexts, must be oneof transient|saved|loaded|all")
)

// ### Main ####################################################################

func main() {
	flag.Parse()

	rwc := tpm.OpenFlush(*tpmPath, *flush)
	defer rwc.Close()

	// Attestor: retrieve EK Pub from TPM
	steps.GetEKPub(rwc, "Attestor/ek")

	//	// Verifier: verify EK Pub with Manufacturer EK Cert
	//	steps.VerifyEKPub("Attestor/ek", "Manufacturer.ek")

	//	// Verifier: create Owner EK Cert
	//	steps.CreateEKCert("Attestor/ek", "Owner/ek")

	return

	steps.CreateAK(rwc)           // On Attestor
	steps.GenerateCredential()    // On Verifier
	steps.ActivateCredential(rwc) // On Attestor
	steps.RequestQuote()          // On Verifier
	steps.PerformQuote(rwc)       // On Attestor
	steps.VerifyQuote()           // On Verifier
	steps.CreateAKCert()          // On Verifier and Owner-CA

	tpm.Clear(rwc) // On Attestor
}
