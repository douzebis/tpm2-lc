// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"

	"main/src/certs"
	"main/src/lib"
)

// ### Verifier: generate credential (challenge) ###############################

func GenerateCredential(
	attestorAkPath string, // IN
	verifierEkPath string, // IN
	verifierNoncePath string, // OUT
	verifierCredentialPath string, // OUT
) {

	lib.PRINT("=== VERIFIER: GENERATE CRED CHALLENGE ==========================================")

	// Retrieve AK name
	akName := lib.Read(fmt.Sprintf("%s-name.blob", attestorAkPath))

	// Verify digest matches the public blob that was provided.
	name, err := tpm2.DecodeName(bytes.NewBuffer(akName))
	if err != nil {
		lib.Fatal("tpm2.DecodeName(): %v", err)
	}
	lib.Comment("akName     : 0x%s", hex.EncodeToString(akName))
	lib.Comment("name.Digest: 0x%04x%s", int(name.Digest.Alg), hex.EncodeToString(name.Digest.Value))

	if name.Digest == nil {
		lib.Fatal("ak.name was not a digest")
	}

	// Retrieve EK Pub
	ekPublicKey := certs.ReadPublicKey(verifierEkPath)

	// Generate a nonce for the credential challenge
	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	if err != nil {
		lib.Fatal("rand.Read() failed: %v", err)
	}

	// Write nonce to disk
	lib.Write(fmt.Sprintf("%s.bin", verifierNoncePath), nonce, 0600)

	// Generate credential challenge for AK name
	symBlockSize := 16
	idObject, encSecret, err := credactivation.Generate(
		name.Digest,  // ak hashed
		&ekPublicKey, // ek public key
		symBlockSize, // sym block size
		nonce,        // secret
	)
	if err != nil {
		lib.Fatal("generate credential: %v", err)
	}

	// Write credential challenge to disk
	lib.Write(fmt.Sprintf("%s-object.blob", verifierCredentialPath), idObject, 0644)
	lib.Write(fmt.Sprintf("%s-secret.blob", verifierCredentialPath), encSecret, 0644)
}
