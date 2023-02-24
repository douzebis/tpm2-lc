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

// ### Main ####################################################################

func main() {
	flag.Parse()

	rwc := tpm.OpenFlush(*tpmPath, *flush)
	defer rwc.Close()

	// Attestor: retrieve EK Pub from TPM
	steps.GetEKPub(rwc, "Attestor/ek")

	// Verifier: verify EK Pub with Manufacturer EK Cert
	steps.VerifyEKPub(
		"Attestor/ek",                  // IN
		"Manufacturer/ek",              // IN
		"Manufacturer/manufacturer-ca", // IN
		"Verifier/ek",                  // OUT
	)

	// Verifier/Owner: create Owner EK Cert
	certs.CreateEKCert(
		"Verifier/ek",      // IN
		"id: Google",       // IN
		"Shielded VM vTPM", // IN
		"id: 00010001",     // IN
		"Owner/owner-ca",   // IN
		"Verifier/ek",      // OUT
	)

	// Attestor: create AK
	steps.CreateAK(
		rwc,
		"Attestor/ek", // OUT
		"Attestor/ak", // OUT
	)

	// Verifier: generate credential challenge
	steps.GenerateCredential(
		"Attestor/ak",         // IN
		"Verifier/ek",         // IN
		"Verifier/nonce",      // OUT
		"Verifier/credential", // OUT
	)
	return

	// Attestor: activate credential
	steps.ActivateCredential(rwc)

	// Verifier: request PCR quote
	steps.RequestQuote()

	// Attestor: perform PCR quote
	steps.PerformQuote(rwc)

	// Verifier: verify PCR quote
	steps.VerifyQuote()

	// Verifier/Owner: create Owner AK Cert
	steps.CreateAKCert()

	// Attestor: clear TPM owner hierarchy
	tpm.Clear(rwc) // On Attestor
}
