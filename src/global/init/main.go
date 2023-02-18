// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
)

var handleNames = map[string][]tpm2.HandleType{
	"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
	"loaded":    {tpm2.HandleTypeLoadedSession},
	"saved":     {tpm2.HandleTypeSavedSession},
	"transient": {tpm2.HandleTypeTransient},
}

var (
	tpmPath = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	flush   = flag.String("flush", "all", "Flush contexts, must be oneof transient|saved|loaded|all")
)

func main() {
	flag.Parse()

	// === Create certificate for TPM CA =======================================

	// Inspired by:
	// https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251
	// https://stackoverflow.com/a/70261780

	// --- Create RSA key for TPM CA -------------------------------------------

	tpmCaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		glog.Fatalf("rsa.GenerateKey() failed: %v", err)
	}

	tpmCaPrivKeyPEM := []byte(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(tpmCaPrivKey),
		},
	))

	err = ioutil.WriteFile("TPM-CA/tpm-ca.key", tpmCaPrivKeyPEM, 0600)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}

	glog.V(10).Infof("Wrote TPM-CA/tpm-ca.key")

	// --- Create Certificate for TPM CA ---------------------------------------

	tpmCaTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"TPM CA"},
			CommonName:   "TPM CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	caBytes, err := x509.CreateCertificate(
		rand.Reader,
		&tpmCaTemplate,
		&tpmCaTemplate,
		&tpmCaPrivKey.PublicKey,
		tpmCaPrivKey)
	if err != nil {
		glog.Fatalf("x509.CreateCertificate() failed: %v", err)
	}

	// pem encode
	caPEM := []byte(pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caBytes,
		},
	))

	err = ioutil.WriteFile("TPM-CA/ca.crt", caPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}

	glog.V(10).Infof("Wrote TPM-CA/ca.crt")

	// --- Create certificate for TPM ------------------------------------------

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("\ncan't close TPM %q: %v", tpmPath, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames[*flush] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			glog.Fatalf("getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				glog.Fatalf("flushing handle 0x%x: %v", handle, err)
			}
			glog.V(2).Infof("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		glog.Fatalf("Unable to load SRK from TPM: %v", err)
	}

	ekPublicKey, _, _, err := tpm2.ReadPublic(rwc, ek.Handle())
	if err != nil {
		glog.Fatalf("tpm2.ReadPublic() failed: %s", err)
	}

	ekp, err := ekPublicKey.Key()
	if err != nil {
		glog.Fatalf("ekPublicKey.Key() failed: %s", err)
	}
	ekBytes, err := x509.MarshalPKIXPublicKey(ekp)
	if err != nil {
		glog.Fatalf("x509.MarshalPKIXPublicKey() failed: %v", err)
	}

	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekBytes,
		},
	)

	err = ioutil.WriteFile("TPM-CA/ek.pem", ekPubPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}

	glog.V(10).Infof("Wrote TPM-CA/ek.pem")

}
