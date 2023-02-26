// SPDX-License-Identifier: Apache-2.0

package main

import (
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

	eventsLog := lib.Read("CICD/event-log.bin")
	parsedEventsLog, err := attest.ParseEventLog(eventsLog)
	if err != nil {
		lib.Fatal("attest.ParseEventLog() failed: %v", err)
	}

	//	attest.EventLog
	//	// EventLog is a parsed measurement log. This contains unverified data representing
	//	// boot events that must be replayed against PCR values to determine authenticity.
	//	type EventLog struct {
	//		// Algs holds the set of algorithms that the event log uses.
	//		Algs []HashAlg
	//		rawEvents   []rawEvent
	//		specIDEvent *specIDEvent
	//	}

	lib.Print("%v", parsedEventsLog.Events(attest.HashAlg(tpm2.AlgSHA256))[0])
	for i, e := range parsedEventsLog.Events(attest.HashAlg(tpm2.AlgSHA256)) {
		lib.Print("%d: %v", i, e)
	}
	return

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
		"Verifier/nonce-quote", // IN
	)

	// Attestor: perform PCR quote
	steps.PerformQuote(rwc)

	// Verifier: verify PCR quote
	steps.VerifyQuote()

	// Verifier/Owner: create Owner AK Cert
	//steps.CreateAKCert(
	//	"TPM AK",         // IN
	//	"Verifier/ak",    // IN/OUT
	//	"Owner/owner-ca", // IN
	//)
	certs.CreateAKCert(
		"Verifier/ak",    // IN
		"TPM AK",         // IN
		"Owner/owner-ca", // IN
		"Verifier/ak",    // OUT
	)

	// Attestor: clear TPM owner hierarchy
	tpm.Clear(rwc) // On Attestor
}
