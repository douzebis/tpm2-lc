// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"flag"

	"main/src/lib"
	"main/src/steps"
	"main/src/teepeem"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	flush   = flag.String("flush", "all", "Flush contexts, must be oneof transient|saved|loaded|all")
)

// ### Main ####################################################################

func main() {
	flag.Parse()

	// Generate random AES26 key
	aesKey := make([]byte, 32)
	_, err := rand.Read(aesKey)
	if err != nil {
		lib.Fatal("rand.Read() failed: %v", err)
	}

	// CICD: seal secret key
	steps.SealKey(
		aesKey,                 // AES256 key
		"Verifier/srk",         // IN
		"CICD/cicd-prediction", // IN
		"CICD/sealed-key",      // OUT
	)

	// Open TPM and Flush handles
	rwc := teepeem.OpenFlush(*tpmPath, *flush)
	defer rwc.Close()

	// Attestor: unseal secret key
	steps.UnsealKey(
		rwc,
		"CICD/sealed-key",       // IN
		"Attestor/unsealed-key", // OUT
	)
}
