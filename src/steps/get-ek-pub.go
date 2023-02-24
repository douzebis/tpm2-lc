// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"

	"main/src/lib"
)

// ### Attestor: get EK Pub### #################################################

func GetEKPub(
	rwc io.ReadWriter,
	ekPath string,
) (
	ekPublicKey *rsa.PublicKey,
	ekPubBytes []byte,
) {

	lib.PRINT("=== ATTESTOR: GET EK PUB =======================================================")

	// === Retrieve TPM EK Pub =================================================

	ek, ekPubKey, err := tpm2.CreatePrimary(
		rwc,
		tpm2.HandleEndorsement,
		tpm2.PCRSelection{},
		"",
		"",
		client.DefaultEKTemplateRSA(),
	)
	if err != nil {
		lib.Fatal("tpm2.CreatePrimary() failed: %v", err)
	}

	ekCtx, err := tpm2.ContextSave(rwc, ek)
	if err != nil {
		lib.Fatal("tpm2.ContextSave() failed: %v", err)
	}

	err = tpm2.FlushContext(rwc, ek)
	if err != nil {
		lib.Fatal("tpm2.FlushContext(0x%x) failed: %v", ek, err)
	}

	lib.Write(fmt.Sprintf("%s.ctx", ekPath), ekCtx, 0644)

	// === Write EK Pub to disk ================================================

	ekPubBytes, err = x509.MarshalPKIXPublicKey(ekPubKey)
	if err != nil {
		lib.Fatal("x509.MarshalPKIXPublicKey() failed: %v", err)
	}

	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekPubBytes,
		},
	)

	lib.Write(fmt.Sprintf("%s.pub", ekPath), ekPubPEM, 0644)

	// Retrieve EK Pub as *rsa.PublicKey
	// See https://stackoverflow.com/a/44317246
	switch ekPubTyp := ekPubKey.(type) {
	case *rsa.PublicKey:
		lib.Print("ekPublicKey is of type RSA")
	default:
		lib.Fatal("ekPublicKey is not of type RSA: %v", ekPubTyp)
	}
	ekPublicKey, _ = ekPubKey.(*rsa.PublicKey)
	lib.Comment("ekPublicKey %v", ekPublicKey)

	return ekPublicKey, ekPubBytes
}
