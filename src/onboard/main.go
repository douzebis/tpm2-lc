// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"flag"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"

	"main/src/certs"
	"main/src/lib"
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
	steps.GetEKPub(
		rwc,
		"Attestor/ek", // OUT
	)

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
		"Attestor/ek", // IN
		"Attestor/ak", // OUT
	)

	// Verifier: generate credential challenge
	steps.GenerateCredential(
		"Attestor/ak",         // IN
		"Verifier/ek",         // IN
		"Verifier/nonce",      // OUT
		"Verifier/credential", // OUT
	)

	// Attestor: activate credential
	steps.ActivateCredential(
		rwc,                   // IN
		"Verifier/credential", // IN
		"Attestor/ek",         // IN
		"Attestor/ak",         // IN
		"Attestor/attempt",    // OUT
	)

	// Verifier: verify credential
	steps.VerifyCredential(
		"Attestor/attempt", // IN
		"Verifier/nonce",   // IN
		"Attestor/ak",      // IN
		"Verifier/ak",      // OUT
	)

	// Verifier: request PCR quote
	steps.RequestQuote(
		"Verifier/nonce-quote", // OUT
	)

	// Attestor: perform PCR quote
	steps.PerformQuote(
		rwc,
		"Verifier/nonce-quote", // IN
		"Attestor/quote",       // OUT
	)

	// Verifier: verify PCR quote
	steps.VerifyQuote(
		"Verifier/ak",          // IN
		"Verifier/nonce-quote", // IN
		"Attestor/quote",       // OUT
	)

	eventsLog := lib.Read("CICD/cicd-digests.bin")
	parsedEventsLog, err := attest.ParseEventLog(eventsLog)
	if err != nil {
		lib.Fatal("attest.ParseEventLog() failed: %v", err)
	}

	pcr0 := [32]byte{}
	lib.Print("pcr0: %v", pcr0)

	lib.Print("%v", parsedEventsLog.Events(attest.HashAlg(tpm2.AlgSHA256))[0])
	for i, e := range parsedEventsLog.Events(attest.HashAlg(tpm2.AlgSHA256)) {
		// sudo cat pcr0.bin zero.bin | openssl dgst -sha256 -binary > futurepcr0.bin
		if e.Index == 0 {
			lib.Print("%d: Index%d: %v", i, e.Index, e.Digest)
			// pcrsConcat = append(pcrsConcat, pcr...)
			// pcrsDigest := sha256.Sum256(pcrsConcat)
			pcr0 = sha256.Sum256(append(pcr0[:], e.Digest...))
			lib.Print("pcr0: %v", pcr0)
		}
	}

	// Verifier/Owner: create Owner AK Cert
	certs.CreateAKCert(
		"Verifier/ak",    // IN
		"TPM AK",         // IN
		"Owner/owner-ca", // IN
		"Verifier/ak",    // OUT
	)

	// Attestor: clear TPM owner hierarchy
	tpm.Clear(rwc) // On Attestor
}
