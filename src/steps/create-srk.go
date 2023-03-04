// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm"

	"main/src/lib"
	"main/src/teepeem"
)

// === Attestor: create SRK ====================================================

func CreateSRK(
	rw io.ReadWriter,
	attestorSrkPath string, // OUT
) {

	lib.PRINT("=== ATTESTOR: CREATE SRK =======================================================")

	// Clear TPM owner hierarchy
	teepeem.Clear(
		rw,
	)
	//	err := tpm.OwnerClear(
	//		rw,
	//		[20]byte{},
	//	)
	//	if err != nil {
	//		lib.Fatal("tpm.OwnerClear() failed: %v", err)
	//	}

	// Compute the auth values as needed.
	var ownerAuth [20]byte
	var srkAuth [20]byte
	pubEK, err := tpm.ReadPubEK(rw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't read the endorsement key: %s\n", err)
		return
	}
	if err := tpm.TakeOwnership(rw, ownerAuth, srkAuth, pubEK); err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't take ownership of the TPM: %s\n", err)
		return
	}

	//	// Prepare template for SRK creation
	//	template := tpm2.Public{
	//		Type:    tpm2.AlgRSA,
	//		NameAlg: tpm2.AlgSHA256,
	//		Attributes: tpm2.FlagFixedTPM | // Key can't leave the TPM.
	//			tpm2.FlagFixedParent | // Key can't change parent.
	//			tpm2.FlagSensitiveDataOrigin | // Key created by the TPM (not imported).
	//			tpm2.FlagUserWithAuth | // Uses (empty) password.
	//			tpm2.FlagNoDA | // This flag doesn't do anything, but it's in the spec.
	//			tpm2.FlagRestricted | // Key used for TPM challenges, not general decryption.
	//			tpm2.FlagDecrypt, // Key can be used to decrypt data.
	//		RSAParameters: &tpm2.RSAParams{
	//			Symmetric: &tpm2.SymScheme{
	//				Alg:     tpm2.AlgAES,
	//				KeyBits: 128,
	//				Mode:    tpm2.AlgCFB,
	//			},
	//			KeyBits:    2048,
	//			ModulusRaw: make([]byte, 256),
	//		},
	//	}
	//
	//	// Create SRK
	//	srk, srkPublicKeyCrypto, err := tpm2.CreatePrimary(
	//		rw,
	//		tpm2.HandleOwner,    // parent
	//		tpm2.PCRSelection{}, // sel
	//		"",                  // parentPassword
	//		"",                  // srkPassword
	//		template,            // template
	//	)

	srkClient, err := client.StorageRootKeyRSA(rw)
	if err != nil {
		lib.Fatal("client.StorageRootKeyRSA() failed: %v", err)
	}
	//	type Key struct {
	//		rw      io.ReadWriter
	//		handle  tpmutil.Handle
	//		pubArea tpm2.Public
	//		pubKey  crypto.PublicKey
	//		name    tpm2.Name
	//		session session
	//		cert    *x509.Certificate
	//	}
	//	srk := srkClient.Handle()
	//	defer tpm2.FlushContext(rw, srk)
	//	if err != nil {
	//		lib.Fatal("tpm2.CreatePrimary() failed for SRK: %v", err)
	//	}
	//
	//	// Save SRK context
	//	srkCtx := teepeem.ContextSave(
	//		rw,
	//		srk,
	//	)
	//
	//	// Write SRK context to disk
	//	lib.Write(fmt.Sprintf("%s.ctx", attestorSrkPath), srkCtx, 0644)

	// Write SRK Pub to disk
	srkPublicKeyDER, err := x509.MarshalPKIXPublicKey(srkClient.PublicKey())
	if err != nil {
		lib.Fatal("x509.MarshalPKIXPublicKey() failed for SRK Pub: %v", err)
	}
	lib.Verbose("ekPublicKeyDER: 0x%s", hex.EncodeToString(srkPublicKeyDER))

	srkPublicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: srkPublicKeyDER,
		},
	)
	lib.Verbose("ekPublicKeyPEM:\n%s", string(srkPublicKeyPEM))

	lib.Write(fmt.Sprintf("%s.pub", attestorSrkPath), srkPublicKeyPEM, 0644)
}
