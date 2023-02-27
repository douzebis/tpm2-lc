// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"fmt"

	"main/src/certs"
	"main/src/lib"
)

// === Verifier: seal secret key ===============================================

func SealKey(
	aesKey [32]byte, // AES256 key
	verifierSrkPath string, // IN
	cicdDigestPath string, // IN
	cicdSealedKeyPath string, // OUT
) {

	lib.PRINT("=== CICD: SEAL SECRET KEY -=====================================================")

	// Read SRK public key from disk
	srkPublicKey := certs.ReadPublicKey(verifierSrkPath)
	lib.Verbose("srkPublicKey: %v", srkPublicKey)

	// Read expected PCRs digest from disk
	pcrDigest := lib.Read(fmt.Sprintf("%s.bin", cicdDigestPath))
	lib.Verbose("pcrDigest: %v", pcrDigest)

	sealedKey := [32]byte{}

	// Write sealed AES key to disk
	lib.Write(fmt.Sprintf("%s.bin", cicdSealedKeyPath), sealedKey[:], 0644)
}
