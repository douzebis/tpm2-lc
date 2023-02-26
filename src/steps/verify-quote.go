// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"encoding/hex"
	"fmt"
	"main/src/lib"

	"github.com/google/go-tpm/tpm2"
)

// ### VerifyQuote (on Verifier) ###############################################
func VerifyQuote(
	verifierAkPath string,
	verifierNoncePath string,
	attestorQuotePath string,
) {

	lib.PRINT("=== VERIFIER: VERIFY QUOTE =====================================================")

	// Read attestation and signature from disk
	attestation := lib.Read(fmt.Sprintf("%s-attest.bin", attestorQuotePath))
	//signature := lib.Read(fmt.Sprint("%s-signature.bin", attestorQuotePath))

	att, err := tpm2.DecodeAttestationData(attestation)
	if err != nil {
		lib.Fatal("DecodeAttestationData() failed: %v", err)
	}

	lib.Verbose("Attestation ExtraData (nonce): %s ", hex.EncodeToString(att.ExtraData))
	lib.Verbose("Attestation PCR#: %v ", att.AttestedQuoteInfo.PCRSelection.PCRs)
	lib.Verbose("Attestation Hash: %v ", hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest))
}
