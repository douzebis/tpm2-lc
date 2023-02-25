// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"bytes"
	"fmt"

	"main/src/certs"
	"main/src/lib"
)

// === Verifier/Owner: create AK Cert ==========================================

func CreateAKCert(
	verifierNoncePath string, // IN
	attestorAttemptPath string, // OUT
	akCertName string, // IN
	verifierAkPath string, // IN/OUT
	ownerCertPath string, //IN
) {

	lib.PRINT("=== VERIFIER/OWNER: CREATE AK CERT =============================================")

	// Retrieve Verifier nonce
	nonce := lib.Read(fmt.Sprintf("%s.bin", verifierNoncePath))

	// Retrieve Attestor attempt
	attempt := lib.Read(fmt.Sprintf("%s.bin", attestorAttemptPath))

	if !bytes.Equal(nonce, attempt) {
		lib.Fatal("Attestor attempt does not match, aborting onboarding")
	}
	lib.Print("Attestor attempt matches Verifier nonce, creating AK cert")

	// Create AK certificate
	certs.CreateAKCert(
		verifierAkPath, // IN
		akCertName,     // IN
		ownerCertPath,  // IN
		verifierAkPath, // OUT
	)
}
