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
	"main/src/teepeem"
)

// === Attestor: get EK Pub ====================================================

func GetEKPub(
	rw io.ReadWriter,
	ekPath string, // OUT
) (
	ekPublicKey *rsa.PublicKey,
	ekPubBytes []byte,
) {

	lib.PRINT("=== ATTESTOR: GET EK PUB =======================================================")

	// Create EK and retrieve EK Pub
	ek, ekPubKey, err := tpm2.CreatePrimary(
		rw,
		tpm2.HandleEndorsement,
		tpm2.PCRSelection{},
		"",
		"",
		client.DefaultEKTemplateRSA(),
	)
	if err != nil {
		lib.Fatal("tpm2.CreatePrimary() failed: %v", err)
	}

	// Save EK context
	ekCtx := teepeem.ContextSave(rw, ek)

	// Write EK context to disk
	lib.Write(fmt.Sprintf("%s.ctx", ekPath), ekCtx, 0644)

	// Flush EK context
	teepeem.FlushContext(rw, ek)

	// Convert EK Pub to PEM
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

	// Write EK Pub to disk
	lib.Write(fmt.Sprintf("%s.pub", ekPath), ekPubPEM, 0644)

	// Assert EK is RSA key
	// See https://stackoverflow.com/a/44317246
	switch ekPubTyp := ekPubKey.(type) {
	case *rsa.PublicKey:
	default:
		lib.Fatal("ekPublicKey is not of type RSA: %v", ekPubTyp)
	}

	// Convert EK Pub to *rsa.PublicKey
	ekPublicKey, _ = ekPubKey.(*rsa.PublicKey)
	lib.Verbose("ekPublicKey %v", ekPublicKey)

	return ekPublicKey, ekPubBytes
}
