// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"main/src/certs"
	"main/src/lib"

	"github.com/google/go-tpm/tpm2"
)

// === Verifier: verify quote ==================================================

func VerifyQuote(
	verifierAkPath string, // IN
	verifierNoncePath string, // IN
	cicdDigestPath string, // IN
	attestorQuotePath string, // OUT
) {

	lib.PRINT("=== VERIFIER: VERIFY QUOTE =====================================================")

	// Read nonce, attestation and signature from disk
	nonce := lib.Read(fmt.Sprintf("%s.bin", verifierNoncePath))
	attestation := lib.Read(fmt.Sprintf("%s-attest.bin", attestorQuotePath))
	signature := lib.Read(fmt.Sprintf("%s-signature.bin", attestorQuotePath))

	att, err := tpm2.DecodeAttestationData(attestation)
	if err != nil {
		lib.Fatal("DecodeAttestationData() failed: %v", err)
	}

	lib.Verbose("Attestation ExtraData (nonce): 0x%s ", hex.EncodeToString(att.ExtraData))
	lib.Verbose("Attestation PCR#: %v ", att.AttestedQuoteInfo.PCRSelection.PCRs)
	lib.Verbose("Attestation Hash: 0x%s ", hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest))

	sigL := tpm2.SignatureRSA{
		HashAlg:   tpm2.AlgSHA256,
		Signature: signature,
	}
	lib.Verbose("sigL: %v", sigL)

	// Read expected PCRs digest from disk
	pcrDigest := lib.Read(fmt.Sprintf("%s.bin", cicdDigestPath))

	//_, pcrHash, err := getPCRMap(tpm.HashAlgo_SHA256)
	//if err != nil {
	//	glog.Fatalf("Error getting PCRMap: %v", err)
	//}
	//glog.V(5).Infof("     sha256 of Expected PCR Value: --> %x", pcrHash)

	if !bytes.Equal(pcrDigest[:], att.AttestedQuoteInfo.PCRDigest) {
		lib.Fatal("Unexpected PCR hash Value Got 0x%s Expected: 0x%s",
			hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest), hex.EncodeToString(pcrDigest[:]))
	}

	// Verify AK signature
	// use the AK from the original attestation to verify the signature of the Attestation
	// rsaPub := rsa.PublicKey{E: int(tPub.RSAParameters.Exponent()), N: tPub.RSAParameters.Modulus()}
	akPublicKey := certs.ReadPublicKey(verifierAkPath)
	hsh := crypto.SHA256.New()
	hsh.Write(attestation)
	err = rsa.VerifyPKCS1v15(
		&akPublicKey,
		crypto.SHA256,
		hsh.Sum(nil),
		sigL.Signature,
	)
	if err != nil {
		lib.Fatal("rsa.VerifyPKCS1v15() failed: %v", err)
	}

	// Now compare the nonce that is embedded within the attestation.  This should match the one we sent in earlier.
	if !bytes.Equal(nonce, att.ExtraData) {
		lib.Fatal("Nonce Value mismatch Got: (0x%s) Expected: (0x%s)",
			hex.EncodeToString(att.ExtraData), hex.EncodeToString(nonce))
	}
}
