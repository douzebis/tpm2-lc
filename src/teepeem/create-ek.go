package tpm

import (
	"crypto"
	"io"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// ### CreateEK (on attestor) ##################################################

func CreateEK(rwc io.ReadWriter) (tpmutil.Handle, crypto.PublicKey, error) {

	// === Create EK ===========================================================

	ek, pub, err := tpm2.CreatePrimary(
		rwc,
		tpm2.HandleEndorsement,
		tpm2.PCRSelection{},
		"", "",
		client.DefaultEKTemplateRSA(),
	)

	return ek, pub, err
}
