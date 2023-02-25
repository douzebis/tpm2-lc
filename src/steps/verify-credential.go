// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"bytes"
	"fmt"

	"main/src/lib"
)

// === Verifier: verify credential =============================================

func VerifyCredential(
	attestorAttemptPath string, // IN
	verifierNoncePath string, // IN
	attestorAkPath string, // IN
	verifierAkPath string, // OUT
) {

	lib.PRINT("=== VERIFIER: VERIFY CREDENTIAL ================================================")

	// Retrieve Attestor attempt
	attempt := lib.Read(fmt.Sprintf("%s.bin", attestorAttemptPath))

	// Retrieve Verifier nonce
	nonce := lib.Read(fmt.Sprintf("%s.bin", verifierNoncePath))

	if !bytes.Equal(nonce, attempt) {
		lib.Fatal("Attestor attempt does not match, aborting onboarding")
	}
	lib.Print("Attestor attempt matches Verifier nonce")

	// Copy AK Pub to Verifier directory
	akPub := lib.Read(fmt.Sprintf("%s.pub", attestorAkPath))
	lib.Write(fmt.Sprintf("%s.pub", verifierAkPath), akPub, 0644)
}
