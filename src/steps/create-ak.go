// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"

	"main/src/lib"
	"main/src/tpm"
)

// === Attestor: create AK =====================================================

func CreateAK(
	rw io.ReadWriter, // IN
	attestorEkPath string, // IN
	attestorAkPath string, // OUT
) {

	lib.PRINT("=== ATTESTOR: CREATE AK ========================================================")

	//	// Create EK in TPM
	//	ek, ekPublicKeyCrypto, err := tpm.CreateEK(rw)
	//	if err != nil {
	//		lib.Fatal("tpm2.CreatePrimary() failed for EK: %v", err)
	//	}
	//	defer tpm2.FlushContext(rw, ek)
	//	lib.Verbose("ek: 0x%08x", ek)
	//	lib.Verbose("ekPublicKey : %v", ekPublicKeyCrypto)
	//
	//	// Save EK context
	//	ekCtx := tpm.ContextSave(rw, ek)
	//
	//	// Flush EK context
	//	tpm.FlushContext(rw, ek)
	//
	//	// Write EK to disk
	//	lib.Write(fmt.Sprintf("%s.ctx", attestorEkPath), ekCtx, 0644)
	//
	//	// Load EK context
	//	ek = tpm.ContextLoad(rw, ekCtx)
	//	defer tpm2.FlushContext(rw, ek)

	// Load EK
	ek := tpm.LoadEK(
		rw,
		attestorEkPath, // IN
	)
	defer tpm2.FlushContext(rw, ek)

	//	// Write EK Pub to disk
	//	ekPublicKeyDER, err := x509.MarshalPKIXPublicKey(ekPublicKeyCrypto)
	//	if err != nil {
	//		lib.Fatal("x509.MarshalPKIXPublicKey() failed for EK Pub: %v", err)
	//	}
	//	lib.Verbose("ekPublicKeyDER: 0x%s", hex.EncodeToString(ekPublicKeyDER))
	//
	//	ekPublicKeyPEM := pem.EncodeToMemory(
	//		&pem.Block{
	//			Type:  "PUBLIC KEY",
	//			Bytes: ekPublicKeyDER,
	//		},
	//	)
	//	lib.Verbose("ekPublicKeyPEM:\n%s", string(ekPublicKeyPEM))
	//
	//	lib.Write(fmt.Sprintf("%s.pub", attestorEkPath), ekPublicKeyPEM, 0644)

	// Auth sessions are required for working with EK children...

	// Start auth session for creating AK
	session := tpm.CreateSession(
		rw,
		tpm2.HandlePasswordSession,
	)
	defer tpm2.FlushContext(rw, session)

	// Create AK
	akPrivateBlob, akPublicBlob, creationData, creationHash, creationTicket,
		err := tpm2.CreateKeyUsingAuth(
		rw,
		ek,                  // owner
		tpm2.PCRSelection{}, // selection
		tpm2.AuthCommand{
			Session:    session,
			Attributes: tpm2.AttrContinueSession,
		}, // authCommand
		"",                     // ownerPassword
		client.AKTemplateRSA(), // template
	)
	if err != nil {
		lib.Fatal("tpm2.CreateKeyUsingAuth() failed: %v", err)
	}
	lib.Verbose("akPrivateBlob 0x%s", hex.EncodeToString(akPrivateBlob))
	lib.Verbose("akPublicBlob 0x%s", hex.EncodeToString(akPublicBlob))
	cr, err := tpm2.DecodeCreationData(creationData)
	if err != nil {
		lib.Fatal("tpm2.DecodeCreationData() failed: %v", err)
	}
	lib.Verbose("CredentialData.ParentName.Digest.Value 0x%s",
		hex.EncodeToString(cr.ParentName.Digest.Value))
	lib.Verbose("CredentialHash 0x%s", hex.EncodeToString(creationHash))
	lib.Verbose("CredentialTicket 0x%s",
		hex.EncodeToString(creationTicket.Digest))

	// Write AK public and private blobs to disk
	lib.Write(fmt.Sprintf("%s-pub.blob", attestorAkPath), akPublicBlob, 0644)
	lib.Write(fmt.Sprintf("%s-priv.blob", attestorAkPath), akPrivateBlob, 0644)

	// Flush Session context
	tpm.FlushContext(rw, session)

	// Load AK
	ak, akName := tpm.LoadAK(
		rw,
		ek,
		attestorAkPath, // IN
	)
	defer tpm2.FlushContext(rw, ak)

	//	// Start auth session for loading AK
	//	session = tpm.CreateSession(
	//		rw,
	//		tpm2.HandlePasswordSession,
	//	)
	//	defer tpm2.FlushContext(rw, session)
	//
	//	// Load AK
	//	ak, akName, err := tpm2.LoadUsingAuth(
	//		rw,
	//		ek, // parentHandle
	//		tpm2.AuthCommand{
	//			Session:    session,
	//			Attributes: tpm2.AttrContinueSession,
	//		}, // authCommand
	//		akPublicBlob,  // publicBlob
	//		akPrivateBlob, // privateBlob
	//	)
	//	if err != nil {
	//		lib.Fatal("tpm2.LoadUsingAuth() failed: %v", err)
	//	}
	//	defer tpm2.FlushContext(rw, ak)
	//	lib.Verbose("ak: 0x%08x", ak)
	//	// akName consists of 36 bytes:
	//	// 00 22: rest is 34 bytes (0x22)
	//	// 00 0b: Algorighm is SHA256
	//	// xx...: 32 bytes for key hash
	//	// See https://github.com/tpm2-software/tpm2-tools/issues/1872
	//	lib.Verbose("akName: 0x%s", hex.EncodeToString(akName))

	// Flush session context
	//tpm.FlushContext(rw, session)

	// Read the public part of AK
	akPublicKey, akName_, akQualName_ := tpm.ReadPublic(
		rw,
		ak,
	)
	//	akPublicKey, akName_, akQualName_, err := tpm2.ReadPublic(
	//			rw,
	//		ak, // handle
	//	)
	//	if err != nil {
	//		lib.Fatal("tpm2.ReadPublic() failed: %v", err)
	//	}
	lib.Verbose("akPublicKey: %v", akPublicKey)
	// akName_ consists of 34 bytes only (size header is missing):
	// 00 0b: Algorighm is SHA256
	// xx...: 32 bytes for key hash
	lib.Verbose("akName_: 0x%s", hex.EncodeToString(akName_))
	lib.Verbose("akQualName2: 0x%s", hex.EncodeToString(akQualName_))

	akPublicKeyCrypto, err := akPublicKey.Key()
	if err != nil {
		lib.Fatal("akTpmPublicKey.Key() failed: %v", err)
	}
	lib.Verbose("akPublicKeyCrypto: %v", akPublicKeyCrypto)
	lib.Verbose("akPublicKeyCrypto.Modulus: 0x%x",
		akPublicKeyCrypto.(*rsa.PublicKey).N)

	akPublicKeyDER, err := x509.MarshalPKIXPublicKey(akPublicKeyCrypto)
	if err != nil {
		lib.Fatal("x509.MarshalPKIXPublicKey() failed: %v", err)
	}
	lib.Verbose("akPublicKeyDER: 0x%s", hex.EncodeToString(akPublicKeyDER))

	akPublicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akPublicKeyDER,
		},
	)
	//	lib.Verbose("akPublicKeyPEM_:\n%v", string(akPublicKeyPEM))

	lib.Write(fmt.Sprintf("%s.pub", attestorAkPath), akPublicKeyPEM, 0644)
	lib.Write(fmt.Sprintf("%s-name.blob", attestorAkPath), akName, 0644)
}
