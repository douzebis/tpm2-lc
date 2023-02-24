// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"

	"main/src/lib"
)

// ### Clear TPM (on Attestor) #################################################

func GetEKPub(
	rwc io.ReadWriter,
	filePrefix string,
) (
	ekPublicKey *rsa.PublicKey,
	ekPubBytes []byte,
) {

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

	lib.Write(filePrefix+".ctx", ekCtx, 0644)

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

	lib.Write(filePrefix+".pem", ekPubPEM, 0644)

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
