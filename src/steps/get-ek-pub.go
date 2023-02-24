// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
)

// ### Clear TPM (on Attestor) #################################################

func GetEKPub(rwc io.ReadWriter) (ekPublicKey *rsa.PublicKey, ekPubBytes []byte) {

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
		glog.Fatalf("tpm2.CreatePrimary() failed: %v", err)
	}

	ekCtx, err := tpm2.ContextSave(rwc, ek)
	if err != nil {
		glog.Fatalf("tpm2.ContextSave() failed: %v", err)
	}
	if err = tpm2.FlushContext(rwc, ek); err != nil {
		glog.Fatalf("tpm2.FlushContext(0x%x) failed: %v", ek, err)
	}
	err = ioutil.WriteFile("Attestor/ek.ctx", ekCtx, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/ek.ctx")

	ekPubBytes, err = x509.MarshalPKIXPublicKey(ekPubKey)
	if err != nil {
		glog.Fatalf("x509.MarshalPKIXPublicKey() failed: %v", err)
	}

	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekPubBytes,
		},
	)

	err = ioutil.WriteFile("Attestor/ek.pem", ekPubPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/ek.pem")

	// From https://stackoverflow.com/a/44317246
	switch ekPubTyp := ekPubKey.(type) {
	case *rsa.PublicKey:
		glog.V(0).Infof("ekPublicKey is of type RSA")
	default:
		glog.Fatalf("ekPublicKey is not of type RSA: %v", ekPubTyp)
	}
	ekPublicKey, _ = ekPubKey.(*rsa.PublicKey)
	glog.V(0).Infof("ekPublicKey %v", ekPublicKey)

	return ekPublicKey, ekPubBytes
}
