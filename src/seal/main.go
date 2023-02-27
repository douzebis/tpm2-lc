// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"

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

	// CICD: seal secret key
	steps.SealKey(
		[32]byte{},                  // AES256 key
		"Verifier/srk",              // IN
		"CICD/CICD/cicd-prediction", // IN
		"CICD/sealed-key",           // OUT
	)

	// Open TPM and Flush handles
	rwc := teepeem.OpenFlush(*tpmPath, *flush)
	defer rwc.Close()
}
