// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
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

	lib.PRINT("=== CICD: PREDICT EXPECTED PCRS VALUES =========================================")

	// Retrieve events log
	eventsLog := lib.Read("CICD/cicd-prediction.bin")
	parsedEventsLog, err := attest.ParseEventLog(eventsLog)
	if err != nil {
		lib.Fatal("attest.ParseEventLog() failed: %v", err)
	}

	// Compute expected PCR values
	pcrs := [][32]byte{}
	for i := 0; i < 24; i++ {
		pcrs = append(pcrs, [32]byte{})
		//lib.Verbose("PCR[%2d]: %v", i, pcrs[i])
		//lib.Verbose("PCR[%2d]: 0x%s", i, hex.EncodeToString(pcrs[i][:]))
	}
	for _, e := range parsedEventsLog.Events(attest.HashAlg(tpm2.AlgSHA256)) {
		// sudo cat pcr.bin digest.bin | openssl dgst -sha256 -binary > futurepcr.bin
		i := e.Index
		pcrs[i] = sha256.Sum256(append(pcrs[i][:], e.Digest...))
		lib.Verbose("PCR[%2d]+0x%s => 0x%s", i,
			hex.EncodeToString(e.Digest), hex.EncodeToString(pcrs[i][:]))
	}

	// Compute attestation digest
	lib.PRINT("=== INIT: PREDICT ATTESTATION DIGEST ===========================================")

	pcrsConcat := []byte{}
	for _, i := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 14} {
		pcrsConcat = append(pcrsConcat, pcrs[i][:]...)
	}
	pcrsDigest := sha256.Sum256(pcrsConcat)

	// Write attestation digest to disk
	lib.Write("CICD/cicd-digest.bin", pcrsDigest[:], 0644)

	// Open TPM and Flush handles
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
		"Attestor/ek",          // IN
		"Attestor/ak",          // IN
		"Verifier/nonce-quote", // IN
		"Attestor/quote",       // OUT
	)

	// Verifier: verify PCR quote
	steps.VerifyQuote(
		"Verifier/ak",          // IN
		"Verifier/nonce-quote", // IN
		"CICD/cicd-digest",     // IN
		"Attestor/quote",       // OUT
	)

	// Verifier/Owner: create Owner AK Cert
	certs.CreateAKCert(
		"Verifier/ak",    // IN
		"TPM AK",         // IN
		"Owner/owner-ca", // IN
		"Verifier/ak",    // OUT
	)

	// Attestor: create SRK
	steps.CreateSRK(
		rwc,
		"Attestor/srk", // OUT
	)

	// Verifier/Owner: create Owner AK Cert
	certs.CreateSRKCert(
		"Attestor/srk",   // IN
		"TPM SRK",        // IN
		"Owner/owner-ca", // IN
		"Verifier/srk",   // OUT
	)
}
