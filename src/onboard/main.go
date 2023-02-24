// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"time"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"

	"main/src/certs"
	"main/src/steps"
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

// ### GenerateCred (on verifier) ##############################################

func GenerateCredential() {

	akName, err := ioutil.ReadFile("Attestor/ak.name")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for ak.name: %v", err)
	}
	glog.V(5).Infof("akName: 0x%s", hex.EncodeToString(akName))

	//	akPublicBlob, err := ioutil.ReadFile("Attestor/ak.pub.blob")
	//	if err != nil {
	//		glog.Fatalf("ioutil.ReadFile() failed for Attestor/ak.pub.blob: %v", err)
	//	}
	//	glog.V(5).Infof("akPublicBlob: %s", string(akPublicBlob))

	//akBlock, _ := pem.Decode(akPublicKeyPEM)
	////akPub, err := x509.ParsePKIXPublicKey(akBlock.Bytes)
	////if err != nil {
	////	glog.Fatalf("x509.ParsePKCS1PrivateKey() failed: %v", err)
	////}
	//akPublicKeyDER := akBlock.Bytes
	//glog.V(0).Infof("akPub2: \n%v", hex.EncodeToString(akPublicKeyDER))

	// Verify digest matches the public blob that was provided.
	name, err := tpm2.DecodeName(bytes.NewBuffer(akName))
	if err != nil {
		glog.Fatalf("tpm2.DecodeName(): %v", err)
	}
	glog.V(5).Infof("akName     : 0x%s", hex.EncodeToString(akName))
	glog.V(5).Infof("name.Digest: 0x%04x%s", int(name.Digest.Alg), hex.EncodeToString(name.Digest.Value))

	if name.Digest == nil {
		glog.Fatalf("ak.name was not a digest")
	}

	//	hash, err := name.Digest.Alg.Hash()
	//	if err != nil {
	//		glog.Fatalf("failed to get name hash: %v", err)
	//	}
	//
	//	pubHash := hash.New()
	//	pubHash.Write(akPublicBlob)
	//	pubDigest := pubHash.Sum(nil)
	//	if !bytes.Equal(name.Digest.Value, pubDigest) {
	//		glog.Fatalf("name was not for public blob")
	//	}
	//
	//	// Inspect key attributes.
	//	pub, err := tpm2.DecodePublic(akPublicBlob)
	//	if err != nil {
	//		glog.Fatalf("decode public blob: %v", err)
	//	}
	//	glog.V(0).Infof("Key attributes: 0x08%x\n", pub.Attributes)

	// Retrieves ekPub
	ekPubPem, err := ioutil.ReadFile("Verifier/ek.pub")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for ek.pub: %v", err)
	}
	ekBlock, _ := pem.Decode(ekPubPem)
	ekPub, err := x509.ParsePKIXPublicKey(ekBlock.Bytes)
	if err != nil {
		glog.Fatalf("x509.ParsePKCS1PrivateKey() failed: %v", err)
	}

	// Generate a challenge for the name.
	secret := make([]byte, 32)
	_, err = rand.Read(secret)
	if err != nil {
		glog.Fatalf("rand.Read() failed: %v", err)
	}

	err = ioutil.WriteFile("Verifier/secret", secret, 0600)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed for Verifier/secret: %v", err)
	}
	glog.V(0).Infof("Wrote Verifier/secret")

	symBlockSize := 16
	credBlob, encSecret, err := credactivation.Generate(name.Digest, ekPub, symBlockSize, secret)
	if err != nil {
		glog.Fatalf("generate credential: %v", err)
	}

	err = ioutil.WriteFile("Verifier/credBlob", credBlob, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed for credBlob: %v", err)
	}
	glog.V(0).Infof("Wrote Verifier/credBlob")

	err = ioutil.WriteFile("Verifier/encSecret", encSecret, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed for encSecret: %v", err)
	}
	glog.V(0).Infof("Wrote Verifier/encSecret")
}

// ### ActivateCredential (on attestor) ########################################

func ActivateCredential(rwc io.ReadWriter) {

	credBlob, err := ioutil.ReadFile("Verifier/credBlob")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for credBlob: %v", err)
	}
	glog.V(0).Infof("Read Verifier/credBlob")

	encSecret, err := ioutil.ReadFile("Verifier/encSecret")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for encSecret: %v", err)
	}
	glog.V(0).Infof("Read Verifier/encSecret")

	ekCtx, err := ioutil.ReadFile("Attestor/ek.ctx")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for EK Ctx: %v", err)
	}
	glog.V(0).Infof("Read Attestor/ek.ctx")

	ek, err := tpm2.ContextLoad(rwc, ekCtx)
	if err != nil {
		glog.Fatalf("tpm2.ContextLoad() failed for EK: %v", err)
	}
	defer tpm2.FlushContext(rwc, ek)

	loadSession, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256,
	)
	if err != nil {
		glog.Fatalf("tpm2.StartAuthSession() failed: %v", err)
	}
	defer tpm2.FlushContext(rwc, loadSession)

	_, _, err = tpm2.PolicySecret(
		rwc,
		tpm2.HandleEndorsement,
		tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
		loadSession,
		nil,
		nil,
		nil,
		0,
	)
	if err != nil {
		glog.Fatalf("tpm2.PolicySecret() failed: %v", err)
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadSession, Attributes: tpm2.AttrContinueSession}

	akPub, err := ioutil.ReadFile("Attestor/ak.pub.blob")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for ak.pub.blob: %v", err)
	}

	akPriv, err := ioutil.ReadFile("Attestor/ak.key.blob")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for ak.key.blob: %v", err)
	}

	ak, _, err := tpm2.LoadUsingAuth(rwc, ek, authCommandLoad, akPub, akPriv)
	if err != nil {
		glog.Fatalf("tpm2.LoadUsingAuth() failed: %v", err)
	}
	defer tpm2.FlushContext(rwc, ak)

	err = tpm2.FlushContext(rwc, loadSession)
	if err != nil {
		glog.Fatalf("tpm2.FlushContext() failed: %v", err)
	}

	session, _, err := tpm2.StartAuthSession(rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("tpm2.StartAuthSession: %v", err)
	}

	auth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	_, _, err = tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, auth, session, nil, nil, nil, 0)
	if err != nil {
		glog.Fatalf("tpm2.AuthCommand: %v", err)
	}

	auths := []tpm2.AuthCommand{auth, {Session: session, Attributes: tpm2.AttrContinueSession}}
	out, err := tpm2.ActivateCredentialUsingAuth(rwc, auths, ak, ek, credBlob[2:], encSecret[2:])
	if err != nil {
		log.Fatalf("activate credential: %v", err)
	}

	err = ioutil.WriteFile("Attestor/secret", out, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed for Attestor/secret: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/secret")

}

// ### RequestQuote (on Verifier) ##############################################
func RequestQuote() {

}

// ### PerformQuote (on Attestor) ##############################################
func PerformQuote(rwc io.ReadWriter) {

}

// ### VerifyQuote (on Verifier) ###############################################
func VerifyQuote() {

}

// ### CreateAKCert (on Verifier and Owner-CA) #################################

func CreateAKCert() {

	referenceSecret, err := ioutil.ReadFile("Verifier/secret")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed: %v", err)
	}

	returnedSecret, err := ioutil.ReadFile("Attestor/secret")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed: %v", err)
	}

	if !bytes.Equal(referenceSecret, returnedSecret) {
		glog.Fatalf("Secrets do not match, aborting onboarding")
	}
	glog.V(0).Infof("Secrets match, creating AK cert")

	// === Retrieve Owner CA key and certificate ===============================

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

	// == Create AK certificate ================================================

	// --- Retrieve AK Pub -----------------------------------------------------

	akPublicKeyPEM, err := ioutil.ReadFile("Attestor/ak.pub")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for Attestor/ak.pub: %v", err)
	}

	akPublicKeyBlock, _ := pem.Decode(akPublicKeyPEM)
	akPublicKeyDER, err := x509.ParsePKIXPublicKey(akPublicKeyBlock.Bytes)
	if err != nil {
		glog.Fatalf("x509.ParsePKCS1PrivateKey() failed: %v", err)
	}

	// --- Create AK certificate -----------------------------------------------

	akTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Owner Inc"},
			CommonName:   "AK",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	akBytes, err := x509.CreateCertificate(
		rand.Reader,
		&akTemplate,
		ownerCaCert,
		akPublicKeyDER,
		ownerCaPrivKey)
	if err != nil {
		glog.Fatalf("x509.CreateCertificate() failed: %v", err)
	}

	// pem encode
	akPEM := []byte(pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: akBytes,
		},
	))

	err = ioutil.WriteFile("Owner-CA/ak.crt", akPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed for Owner-CA/ak.crt: %v", err)
	}
	glog.V(0).Infof("Wrote Owner-CA/ak.crt")

	// --- Verify TPM cert -----------------------------------------------------

	// Note: equivalently with openssl:
	// openssl verify -CAfile TPM-CA/tpm-ca.crt TPM-CA/tpm.crt
	// openssl x509 -noout -ext subjectAltName -in TPM-CA/tpm.crt

	akOwnerCert, err := x509.ParseCertificate(akBytes)
	if err != nil {
		glog.Fatalf("x509.ParseCertificate() failed: %v", err)
	}
	//akOwnerCert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}
	if _, err := akOwnerCert.Verify(ownerOpts); err != nil {
		glog.Fatalf("akOwnerCert.Verify() failed: %v", err)
	} else {
		glog.V(0).Infof("Verified %s", "Owner-CA/ak.crt")
	}
}

// ### Main ####################################################################

func toto(format string, params ...interface{}) {
	glog.V(0).Infof(format, params...)
}

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
		*certs.CreateSubjectAltName(
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

	ekPubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekPubBytes,
		},
	)

	err = ioutil.WriteFile("Verifier/ek.pub", ekPubPem, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed for EK Pub: %v", err)
	}
	glog.V(0).Infof("Wrote Verifier/ek.pub")

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
			*certs.CreateSubjectAltName(
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

	steps.CreateAK(rwc)     // On Attestor
	GenerateCredential()    // On Verifier
	ActivateCredential(rwc) // On Attestor
	RequestQuote()          // On Verifier
	PerformQuote(rwc)       // On Attestor
	VerifyQuote()           // On Verifier
	CreateAKCert()          // On Verifier and Owner-CA

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
