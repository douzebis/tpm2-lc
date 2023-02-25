// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"main/src/certs"
	"main/src/lib"
)

// === Verifier/Owner: create AK Cert ==========================================

func CreateAKCert(
	akCertName string, // IN
	verifierAkPath string, // IN/OUT
	ownerCertPath string, //IN
) {

	lib.PRINT("=== VERIFIER/OWNER: CREATE AK CERT =============================================")

	// Create AK certificate
	certs.CreateAKCert(
		verifierAkPath, // IN
		akCertName,     // IN
		ownerCertPath,  // IN
		verifierAkPath, // OUT
	)
}
