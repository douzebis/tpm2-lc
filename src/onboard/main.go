// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"io/ioutil"

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

	// === Open TPM device and flush key handles ===============================

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

	// === Retrieve TPM EK Pub =================================================

	ekTpmKey, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		glog.Fatalf("Unable to load SRK from TPM: %v", err)
	}

	ekTpmPubKey, _, _, err := tpm2.ReadPublic(rwc, ekTpmKey.Handle())
	if err != nil {
		glog.Fatalf("tpm2.ReadPublic() failed: %s", err)
	}

	ekPubKey, err := ekTpmPubKey.Key()
	if err != nil {
		glog.Fatalf("ekPublicKey.Key() failed: %s", err)
	}
	ekPubBytes, err := x509.MarshalPKIXPublicKey(ekPubKey)
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
	ekPublicKey, _ := ekPubKey.(*rsa.PublicKey)
	glog.V(0).Infof("ekPublicKey %v", ekPublicKey)

	// === Verify TPM EK Pub with TPM manufacturer =============================

	// --- Read TPM Manufacturer CA cert ---------------------------------------

	tpmCaPem, err := ioutil.ReadFile("TPM-CA/tpm-ca.crt")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed: %v", err)
	}
	//glog.V(0).Infof("TPM-CA/tpm-ca.crt:\n%s", string(tpmCaPem))

	tpmCaBlock, _ := pem.Decode(tpmCaPem)
	tpmCaCert, err := x509.ParseCertificate(tpmCaBlock.Bytes)
	if err != nil {
		glog.Fatalf("x509.ParseCertificate() failed: %v", err)
	}

	// --- Check TPM Manufacturer CA cert --------------------------------------

	roots := x509.NewCertPool()
	roots.AddCert(tpmCaCert)
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := tpmCaCert.Verify(opts); err != nil {
		glog.Fatalf("tpmCaCert.Verify() failed: %v", err)
	} else {
		glog.V(0).Infof("Verified %s", "TPM-CA/tpm-ca.crt")
	}

	// --- Read TPM cert -------------------------------------------------------

	tpmPem, err := ioutil.ReadFile("TPM-CA/tpm.crt")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed: %v", err)
	}
	//glog.V(0).Infof("TPM-CA/tpm.crt:\n%s", string(tpmPem))

	tpmBlock, _ := pem.Decode(tpmPem)
	tpmCert, err := x509.ParseCertificate(tpmBlock.Bytes)
	if err != nil {
		glog.Fatalf("x509.ParseCertificate() failed: %v", err)
	}
	//pubkey := tpmCert.PublicKey.(*rsa.PublicKey)

	// --- Check TPM Manufacturer CA cert --------------------------------------

	//unhandledCriticalExtensions := tpmCert.UnhandledCriticalExtensions
	tpmCert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}

	if _, err := tpmCert.Verify(opts); err != nil {
		glog.Fatalf("tpmCert.Verify() failed: %v", err)
	} else {
		glog.V(0).Infof("Verified %s", "TPM-CA/tpm.crt")
	}

	// --- Check TPM EK Pub matches TPM cert -----------------------------------

	toto, err := x509.MarshalPKIXPublicKey(tpmCert.PublicKey)
	if err != nil {
		glog.Fatalf("x509.MarshalPKIXPublicKey() failed: %v", err)
	}

	//a := tpmCert.PublicKey.(*rsa.PublicKey)
	if !bytes.Equal(ekPubBytes, toto) {
		glog.Fatalf("EK Pub does not match with TPM certificate")
	}
}