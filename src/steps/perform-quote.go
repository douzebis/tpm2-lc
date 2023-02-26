// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"main/src/lib"
	"main/src/tpm"
)

// ### PerformQuote (on Attestor) ##############################################
func PerformQuote(
	rw io.ReadWriter,
	attestorEkPath, // IN
	attestorAkPath, // IN
	verifierNoncePath string, // IN
	attestorQuotePath string, // OUT
) (
	attestation []byte,
	signature tpmutil.U16Bytes,
) {

	lib.PRINT("=== ATTESTOR: PERFORM QUOTE ====================================================")

	// Load EK
	ek := tpm.LoadEK(
		rw,
		attestorEkPath,
	)
	defer tpm2.FlushContext(rw, ek)

	// Load AK
	ak, _ := tpm.LoadAK(
		rw,
		ek,
		attestorAkPath, // IN
	)
	defer tpm2.FlushContext(rw, ak)

	// Load nonce
	nonce := lib.Read(fmt.Sprintf("%s.bin", verifierNoncePath))

	// Perform quote
	pcrSelection := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 14},
	}
	attestation, sig, err := tpm2.Quote(
		rw,
		ak,
		"", // emptyPassword
		"", // emptyPassword
		nonce,
		pcrSelection,
		tpm2.AlgNull,
	)
	if err != nil {
		lib.Fatal("tpm2.Quote() failed: %v", err)
	}
	signature = sig.RSA.Signature
	lib.Verbose("     Quote Hex %v", hex.EncodeToString(attestation))
	lib.Verbose("     Quote Sig %v", hex.EncodeToString(signature))

	// Write quote to disk
	lib.Write(fmt.Sprintf("%s-attest.bin", attestorQuotePath), attestation, 0644)
	lib.Write(fmt.Sprintf("%s-signature.bin", attestorQuotePath), signature, 0644)

	return attestation, signature
}
