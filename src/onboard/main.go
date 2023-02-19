// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"main/src/lib"
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

	tpmRoots := x509.NewCertPool()
	tpmRoots.AddCert(tpmCaCert)
	tpmOpts := x509.VerifyOptions{
		Roots: tpmRoots,
	}

	if _, err := tpmCaCert.Verify(tpmOpts); err != nil {
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

	// --- Check TPM cert ------------------------------------------------------

	unhandledCriticalExtensions := tpmCert.UnhandledCriticalExtensions
	glog.V(0).Infof("uce %v", unhandledCriticalExtensions)

	tpmCert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}

	if _, err := tpmCert.Verify(tpmOpts); err != nil {
		glog.Fatalf("tpmCert.Verify() failed: %v", err)
	} else {
		glog.V(0).Infof("Verified %s", "TPM-CA/tpm.crt")
	}

	// --- Check SAN in TPM cert -----------------------------------------------

	subjectAltName := asn1.ObjectIdentifier{2, 5, 29, 17}

	if len(unhandledCriticalExtensions) != 1 {
		glog.Fatalf("Unexpected UnhandledCriticalExtensions: %v",
			unhandledCriticalExtensions)
	}
	if !unhandledCriticalExtensions[0].Equal(subjectAltName) {
		glog.Fatalf("OID is not SAN: %v", unhandledCriticalExtensions[0])
	}

	expectedSAN := pkix.Extension(
		*lib.CreateSubjectAltName(
			[]byte("id: Google"),
			[]byte("id: Shielded VM vTPM"),
			[]byte("id: 00010001"),
		),
	)

	for _, ext := range tpmCert.Extensions {
		if ext.Id.Equal(subjectAltName) {
			if !ext.Critical {
				glog.Fatalf("SAN should be critical")
			}
			if !ext.Id.Equal(expectedSAN.Id) || !bytes.Equal(ext.Value, expectedSAN.Value) {
				glog.Fatalf("SAN has unexpected value: %v", ext)

			}
		}
	}

	// --- Check TPM EK Pub matches TPM cert -----------------------------------

	certPubBytes, err := x509.MarshalPKIXPublicKey(tpmCert.PublicKey)
	if err != nil {
		glog.Fatalf("x509.MarshalPKIXPublicKey() failed: %v", err)
	}

	if !bytes.Equal(ekPubBytes, certPubBytes) {
		glog.Fatalf("EK Pub does not match TPM certificate")
	}
	glog.V(0).Infof("EK Pub matches TPM certificate")

	// === Create Owner certificate for EK Pub =================================

	// --- Read Owner CA cert --------------------------------------------------

	ownerCaPem, err := ioutil.ReadFile("Owner-CA/owner-ca.crt")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed: %v", err)
	}

	ownerCaBlock, _ := pem.Decode(ownerCaPem)
	ownerCaCert, err := x509.ParseCertificate(ownerCaBlock.Bytes)
	if err != nil {
		glog.Fatalf("x509.ParseCertificate() failed: %v", err)
	}

	// --- Check Owner CA cert -------------------------------------------------

	ownerRoots := x509.NewCertPool()
	ownerRoots.AddCert(ownerCaCert)
	ownerOpts := x509.VerifyOptions{
		Roots: ownerRoots,
	}

	if _, err := ownerCaCert.Verify(ownerOpts); err != nil {
		glog.Fatalf("ownerCaCert.Verify() failed: %v", err)
	} else {
		glog.V(0).Infof("Verified %s", "Owner-CA/owner-ca.crt")
	}

	// --- Read Owner CA key ---------------------------------------------------

	ownerCaPrivKeyPem, err := ioutil.ReadFile("Owner-CA/owner-ca.key")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed: %v", err)
	}

	ownerCaPrivKeyBlock, _ := pem.Decode(ownerCaPrivKeyPem)
	ownerCaPrivKey, err := x509.ParsePKCS1PrivateKey(ownerCaPrivKeyBlock.Bytes)
	if err != nil {
		glog.Fatalf("x509.ParsePKCS1PrivateKey() failed: %v", err)
	}

	// --- Create TPM EK certificate -------------------------------------------

	tpmTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Owner Inc"},
			CommonName:   "TPM",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		KeyUsage:  x509.KeyUsageKeyEncipherment,
		ExtraExtensions: []pkix.Extension{
			*lib.CreateSubjectAltName(
				[]byte("id: Google"),
				[]byte("id: Shielded VM vTPM"),
				[]byte("id: 00010001"),
			),
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	tpmBytes, err := x509.CreateCertificate(
		rand.Reader,
		&tpmTemplate,
		ownerCaCert,
		ekPublicKey,
		ownerCaPrivKey)
	if err != nil {
		glog.Fatalf("x509.CreateCertificate() failed: %v", err)
	}

	// pem encode
	tpmPEM := []byte(pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: tpmBytes,
		},
	))

	err = ioutil.WriteFile("Owner-CA/tpm.crt", tpmPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}

	glog.V(0).Infof("Wrote Owner-CA/tpm.crt")

	// --- Verify TPM cert -----------------------------------------------------

	// Note: equivalently with openssl:
	// openssl verify -CAfile TPM-CA/tpm-ca.crt TPM-CA/tpm.crt
	// openssl x509 -noout -ext subjectAltName -in TPM-CA/tpm.crt

	tpmOwnerCert, err := x509.ParseCertificate(tpmBytes)
	if err != nil {
		glog.Fatalf("x509.ParseCertificate() failed: %v", err)
	}
	tpmOwnerCert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}
	if _, err := tpmOwnerCert.Verify(ownerOpts); err != nil {
		glog.Fatalf("tpmOwnerCert.Verify() failed: %v", err)
	} else {
		glog.V(0).Infof("Verified %s", "Owner-CA/tpm.crt")
	}

	// === Create TPM AK =======================================================

	pcrSelection0 := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{},
	}
	emptyPassword := ""

	//ek, pub, err := tpm2.CreatePrimary(f, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", tmpl)
	//if err != nil {
	//		log.Fatalf("creating ek: %v", err)
	//}
	ekCtx, err := tpm2.ContextSave(rwc, ekTpmKey.Handle())
	if err != nil {
		glog.Fatalf("tpm2.ContextSave() failed: %v", err)
	}
	err = ioutil.WriteFile("Attestor/ek.ctx", ekCtx, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}

	//akPriv, akPub, creationData, creationHash, creationTicket, err := tpm2.CreateKey(
	_, _, _, _, _, err = tpm2.CreateKey(
		rwc,
		ekTpmKey.Handle(),
		pcrSelection0,
		emptyPassword,
		emptyPassword,
		client.AKTemplateRSA(),
	)
	if err != nil {
		glog.Fatalf("tpm2.CreateKey: %v", err)
	}

	// === Clear TPM ===========================================================

	err = tpm2.Clear(
		rwc,
		tpm2.HandlePlatform,
		tpm2.AuthCommand{
			Session:    tpm2.HandlePasswordSession,
			Attributes: tpm2.AttrContinueSession,
			// See https://github.com/google/go-tpm/issues/157
			Auth: make([]byte, 20), // The empty password
		},
	)
	if err != nil {
		glog.Fatalf("tpm2.Clear() failed: %v", err)
	}

}
