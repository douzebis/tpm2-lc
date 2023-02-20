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
	"main/src/lib"
	"math/big"
	"time"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
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

// ### GetAK (on attestor) #####################################################

func CreateAK(rwc io.ReadWriter) {

	// === Load EK =============================================================

	ek, _, err := tpm2.CreatePrimary(
		rwc,
		tpm2.HandleEndorsement,
		tpm2.PCRSelection{},
		"", "",
		client.DefaultEKTemplateRSA(),
	)
	if err != nil {
		glog.Fatalf("tpm2.CreatePrimary() failed for EK: %v", err)
	}
	defer tpm2.FlushContext(rwc, ek)

	tpmEkPub, _, _, err := tpm2.ReadPublic(rwc, ek)
	if err != nil {
		glog.Fatalf("tpm2.ReadPublic() failed for EK: %v", err)
	}

	ekPub, err := tpmEkPub.Key()
	if err != nil {
		glog.Fatalf("tpmEkPub.Key() failed for EK: %v", err)
	}

	ekPubBytes, err := x509.MarshalPKIXPublicKey(ekPub)
	if err != nil {
		glog.Fatalf("x509.MarshalPKIXPublicKey() failed for EK Pub: %v", err)
	}

	ekPubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekPubBytes,
		},
	)

	err = ioutil.WriteFile("Attestor/ek.pub", ekPubPem, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed for EK Pub: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/ek.pub")

	//tpmEkPubBytes, err := tpmEkPub.Encode()
	_, err = tpmEkPub.Encode()
	if err != nil {
		glog.Fatalf("tpmEkPub.Encode() failed: %v", err)
	}

	// === Start auth session for AK creation ==================================

	// /!\ Creating AK as child of EK requires an auth session

	createSession, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("tpm2.StartAuthSession() failed for AK: %v", err)
	}
	defer tpm2.FlushContext(rwc, createSession)

	_, _, err = tpm2.PolicySecret(
		rwc,
		tpm2.HandleEndorsement,
		tpm2.AuthCommand{
			Session:    tpm2.HandlePasswordSession,
			Attributes: tpm2.AttrContinueSession},
		createSession,
		nil,
		nil,
		nil,
		0,
	)
	if err != nil {
		glog.Fatalf("tpm2.PolicySecret() failed for create session: %v", err)
	}

	authCommandCreateAuth := tpm2.AuthCommand{Session: createSession,
		Attributes: tpm2.AttrContinueSession}

	// === Create AK ===========================================================

	akPriv, akPub, creationData, creationHash, creationTicket, err := tpm2.CreateKeyUsingAuth(
		rwc,
		ek,
		tpm2.PCRSelection{},
		authCommandCreateAuth,
		"",
		client.AKTemplateRSA(),
	)
	if err != nil {
		glog.Fatalf("tpm2.CreateKeyUsingAuth() failed for AK: %v", err)
	}

	err = tpm2.FlushContext(rwc, createSession)
	if err != nil {
		glog.Fatalf("tpm2.FlushContext() failed: %v", err)
	}

	glog.V(10).Infof("     akPub: %s,", hex.EncodeToString(akPub))
	glog.V(10).Infof("     akPriv: %s,", hex.EncodeToString(akPriv))

	cr, err := tpm2.DecodeCreationData(creationData)
	if err != nil {
		glog.Fatalf("tpm2.DecodeCreationData() failed: %v", err)
	}

	glog.V(10).Infof("     CredentialData.ParentName.Digest.Value %s", hex.EncodeToString(cr.ParentName.Digest.Value))
	glog.V(10).Infof("     CredentialTicket %s", hex.EncodeToString(creationTicket.Digest))
	glog.V(10).Infof("     CredentialHash %s", hex.EncodeToString(creationHash))

	// === Flush and reload EK =================================================

	ekCtx, err := tpm2.ContextSave(rwc, ek)
	if err != nil {
		glog.Fatalf("tpm2.ContextSave() failed for EK: %v", err)
	}
	err = ioutil.WriteFile("Attestor/ek.ctx", ekCtx, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed for EK Ctx: %v", err)
	}
	tpm2.FlushContext(rwc, ek)

	ekCtx, err = ioutil.ReadFile("Attestor/ek.ctx")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for EK Ctx: %v", err)
	}
	ek, err = tpm2.ContextLoad(rwc, ekCtx)
	if err != nil {
		glog.Fatalf("tpm2.ContextLoad() failed for EK: %v", err)
	}
	defer tpm2.FlushContext(rwc, ek)

	// === Start auth session for loading AK ===================================

	// /!\ Loading AK as child of EK requires an auth session

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

	// === Load AK =============================================================

	ak, akName0, err := tpm2.LoadUsingAuth(rwc, ek, authCommandLoad, akPub, akPriv)
	if err != nil {
		glog.Fatalf("tpm2.LoadUsingAuth() failed: %v", err)
	}
	defer tpm2.FlushContext(rwc, ak)

	err = tpm2.FlushContext(rwc, loadSession)
	if err != nil {
		glog.Fatalf("tpm2.FlushContext() failed: %v", err)
	}

	glog.V(0).Infof("AK keyName0 %s", hex.EncodeToString(akName0))

	akTpmPublicKey, akName, _, err := tpm2.ReadPublic(rwc, ak)
	if err != nil {
		glog.Fatalf("tpm2.ReadPublic() failed: %v", err)
	}

	akPublicKey, err := akTpmPublicKey.Key()
	if err != nil {
		glog.Fatalf("akTpmPublicKey.Key() failed: %v", err)
	}
	akBytes, err := x509.MarshalPKIXPublicKey(akPublicKey)
	if err != nil {
		glog.Fatalf("x509.MarshalPKIXPublicKey() failed: %v", err)
	}

	akPubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)
	glog.V(0).Infof("akPubPEM: \n%v", string(akPubPem))

	glog.V(0).Infof("akPub: \n%v", hex.EncodeToString(akPub))
	glog.V(0).Infof("akPub: \n%v", akPub)
	glog.V(0).Infof("akBytes: \n%v", hex.EncodeToString(akBytes))
	glog.V(0).Infof("akBytes: \n%v", akBytes)

	akPubBytes2, err := akTpmPublicKey.Encode()
	if err != nil {
		glog.Errorf("ERROR: Encoding failed for akPubBytes: %v", err)
	}
	tPub, err := tpm2.DecodePublic(akPubBytes2)
	if err != nil {
		glog.Fatalf("Error DecodePublic AK %v", tPub)
	}
	ap, err := tPub.Key()
	if err != nil {
		glog.Fatalf("akPub.Key() failed: %s", err)
	}
	akBytes2, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		glog.Fatalf("Unable to convert akPub: %v", err)
	}
	glog.V(0).Infof("akBytes: \n%v", hex.EncodeToString(akBytes2))

	err = ioutil.WriteFile("Attestor/ak.pub", akPubPem, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/ak.pub")

	err = ioutil.WriteFile("Attestor/ak.key", akPriv, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/ak.key")

	akPubBytes, err := akTpmPublicKey.Encode()
	if err != nil {
		glog.Fatalf("akTpmPublicKey.Encode() failed: %v", err)
	}
	glog.V(10).Infof("EkPub %v", ekPubBytes)
	glog.V(10).Infof("AkName %v", akName)
	glog.V(10).Infof("AkPub %v", akPubBytes)

	err = ioutil.WriteFile("Attestor/ak.name", akName0, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed for ak.name: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/ak.name")
}

// ### GenerateCred (on verifier) ##############################################

func GenerateCredential() {

	akName, err := ioutil.ReadFile("Attestor/ak.name")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for ak.name: %v", err)
	}

	//akPubPem, err := ioutil.ReadFile("Attestor/ak.pub")
	//if err != nil {
	//	glog.Fatalf("ioutil.ReadFile() failed for ak.pub: %v", err)
	//}
	//akBlock, _ := pem.Decode(akPubPem)
	//akPub, err := x509.ParsePKIXPublicKey(akBlock.Bytes)
	//if err != nil {
	//	glog.Fatalf("x509.ParsePKCS1PrivateKey() failed: %v", err)
	//}
	akPub := []byte{}

	// Verify digest matches the public blob that was provided.
	name, err := tpm2.DecodeName(bytes.NewBuffer(akName))
	if err != nil {
		glog.Fatalf("tpm2.DecodeName(): %v", err)
	}
	if name.Digest == nil {
		glog.Fatalf("ak.name was not a digest")
	}

	h, err := name.Digest.Alg.Hash()
	if err != nil {
		glog.Fatalf("failed to get name hash: %v", err)
	}
	pubHash := h.New()
	pubHash.Write(akPub)
	pubDigest := pubHash.Sum(nil)
	if !bytes.Equal(name.Digest.Value, pubDigest) {
		glog.Fatalf("name was not for public blob")
	}

	// Inspect key attributes.
	pub, err := tpm2.DecodePublic(akPub)
	if err != nil {
		glog.Fatalf("decode public blob: %v", err)
	}
	glog.V(0).Infof("Key attributes: 0x08%x\n", pub.Attributes)

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
	secret := []byte("The quick brown fox jumps over the lazy dog")
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

// ### GetAK (on attestor) #####################################################

func ActivateCredential(rwc io.ReadWriter) {

	credBlob, err := ioutil.ReadFile("Verifier/credBlob")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for credBlob: %v", err)
	}

	encSecret, err := ioutil.ReadFile("Verifier/encSecret")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for encSecret: %v", err)
	}

	ekCtx, err := ioutil.ReadFile("Attestor/ek.ctx")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for EK Ctx: %v", err)
	}

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

	akPub, err := ioutil.ReadFile("Attestor/ak.pub")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for ak.pub: %v", err)
	}

	akPriv, err := ioutil.ReadFile("Attestor/ak.key")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for ak.key: %v", err)
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
	glog.V(0).Infof("Secret; %s", out)
}

// ### Main ####################################################################

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

	//ekTpmKey, err := client.EndorsementKeyRSA(rwc)
	//if err != nil {
	//	glog.Fatalf("Unable to load SRK from TPM: %v", err)
	//}
	//
	//ekTpmPubKey, _, _, err := tpm2.ReadPublic(rwc, ekTpmKey.Handle())
	//if err != nil {
	//	glog.Fatalf("tpm2.ReadPublic() failed: %s", err)
	//}
	//
	//ekPubKey, err := ekTpmPubKey.Key()
	//if err != nil {
	//	glog.Fatalf("ekPublicKey.Key() failed: %s", err)
	//}

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

	CreateAK(rwc) // On the Attestor

	// === Create credential challenge =========================================

	GenerateCredential() // On the Verifier

	// === Activate credential =================================================

	ActivateCredential(rwc)

	//	ek, err = tpm2.ContextLoad(rwc, ekCtx)
	//	if err != nil {
	//		glog.Fatalf("tpm2.ContextLoad() failed: %v", err)
	//	}
	//
	//	sessCreateHandle, _, err := tpm2.StartAuthSession(
	//		rwc,
	//		tpm2.HandleNull,
	//		tpm2.HandleNull,
	//		make([]byte, 16),
	//		nil,
	//		tpm2.SessionPolicy,
	//		tpm2.AlgNull,
	//		tpm2.AlgSHA256)
	//	if err != nil {
	//		glog.Fatalf("ERROR:   Unable to create StartAuthSession: %v", err)
	//	}
	//	defer tpm2.FlushContext(rwc, sessCreateHandle)
	//
	//	_, _, err = tpm2.PolicySecret(
	//		rwc,
	//		tpm2.HandleEndorsement,
	//		tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
	//		sessCreateHandle,
	//		nil,
	//		nil,
	//		nil,
	//		0,
	//	)
	//	if err != nil {
	//		glog.Fatalf("tpm2.PolicySecret() failed: %v", err)
	//	}
	//
	//	authCommandCreateAuth := tpm2.AuthCommand{Session: sessCreateHandle, Attributes: tpm2.AttrContinueSession}
	//
	//	// /!\ Creating a key child of EK requires Auth Session
	//
	//	akPriv, akPub, creationData, creationHash, creationTicket, err := tpm2.CreateKeyUsingAuth(
	//		//akPriv, akPub, _, _, _, err := tpm2.CreateKeyUsingAuth(
	//		rwc,
	//		ek,
	//		tpm2.PCRSelection{},
	//		authCommandCreateAuth,
	//		"",
	//		client.AKTemplateRSA(),
	//	)
	//	if err != nil {
	//		glog.Fatalf("tpm2.CreateKeyUsingAuth() failed: %v", err)
	//	}
	//
	//	err = tpm2.FlushContext(rwc, sessCreateHandle)
	//	if err != nil {
	//		glog.Fatalf("tpm2.FlushContext() failed: %v", err)
	//	}
	//
	//	glog.V(0).Infof("     akPub: %s,", hex.EncodeToString(akPub))
	//	glog.V(0).Infof("     akPriv: %s,", hex.EncodeToString(akPriv))
	//
	//	cr, err := tpm2.DecodeCreationData(creationData)
	//	if err != nil {
	//		glog.Fatalf("tpm2.DecodeCreationData() failed: %v", err)
	//	}
	//
	//	glog.V(0).Infof("     CredentialData.ParentName.Digest.Value %s", hex.EncodeToString(cr.ParentName.Digest.Value))
	//	glog.V(0).Infof("     CredentialTicket %s", hex.EncodeToString(creationTicket.Digest))
	//	glog.V(0).Infof("     CredentialHash %s", hex.EncodeToString(creationHash))
	//
	//	// === Load TPM AK (requires Auth Session) =================================
	//
	//	loadSession, _, err := tpm2.StartAuthSession(
	//		rwc,
	//		tpm2.HandleNull,
	//		tpm2.HandleNull,
	//		make([]byte, 16),
	//		nil,
	//		tpm2.SessionPolicy,
	//		tpm2.AlgNull,
	//		tpm2.AlgSHA256,
	//	)
	//	if err != nil {
	//		glog.Fatalf("tpm2.StartAuthSession() failed : %v", err)
	//	}
	//	//defer tpm2.FlushContext(rwc, loadSession)
	//
	//	_, _, err = tpm2.PolicySecret(
	//		rwc,
	//		tpm2.HandleEndorsement,
	//		tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
	//		loadSession,
	//		nil,
	//		nil,
	//		nil,
	//		0,
	//	)
	//	if err != nil {
	//		glog.Fatalf("tpm2.PolicySecret() failed: %v", err)
	//	}
	//
	//	authCommandLoad := tpm2.AuthCommand{Session: loadSession, Attributes: tpm2.AttrContinueSession}
	//
	//	ak, akName, err := tpm2.LoadUsingAuth(rwc, ek, authCommandLoad, akPub, akPriv)
	//	if err != nil {
	//		glog.Fatalf("tpm2.LoadUsingAuth() failed: %v", err)
	//	}
	//	//defer tpm2.FlushContext(rwc, keyHandle)
	//
	//	err = tpm2.FlushContext(rwc, loadSession)
	//	if err != nil {
	//		glog.Fatalf("tpm2.FlushContext() failed: %v", err)
	//	}
	//
	//	akn := hex.EncodeToString(akName)
	//	glog.V(0).Infof("AK keyName %s", akn)
	//
	//	akTpmPublicKey, akName, _, err := tpm2.ReadPublic(rwc, ak)
	//	if err != nil {
	//		glog.Fatalf("tpm2.ReadPublic() failed: %v", err)
	//	}
	//	//if !bytes.Equal(akName, akName2) {
	//	//	glog.Fatalf("akName and akName2 differ\n%v\n%v", akName, akName2)
	//	//}
	//
	//	akPublicKey, err := akTpmPublicKey.Key()
	//	if err != nil {
	//		glog.Fatalf("akTpmPublicKey.Key() failed: %v", err)
	//	}
	//	akBytes, err := x509.MarshalPKIXPublicKey(akPublicKey)
	//	if err != nil {
	//		glog.Fatalf("x509.MarshalPKIXPublicKey() failed: %v", err)
	//	}
	//
	//	akPubPEM := pem.EncodeToMemory(
	//		&pem.Block{
	//			Type:  "PUBLIC KEY",
	//			Bytes: akBytes,
	//		},
	//	)
	//	glog.V(0).Infof("akPubPEM: \n%v", string(akPubPEM))
	//
	//	err = ioutil.WriteFile("Attestor/ak.pub", akPub, 0644)
	//	if err != nil {
	//		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	//	}
	//	glog.V(0).Infof("Wrote Attestor/ak.pub")
	//
	//	err = ioutil.WriteFile("Attestor/ak.key", akPriv, 0644)
	//	if err != nil {
	//		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	//	}
	//	glog.V(0).Infof("Wrote Attestor/ak.key")
	//	akPubBytes, err := akTpmPublicKey.Encode()
	//	if err != nil {
	//		glog.Fatalf("akTpmPublicKey.Encode() failed: %v", err)
	//	}
	//	glog.V(0).Infof("EkPub %v", ekPubBytes)
	//	glog.V(0).Infof("AkName %v", akName)
	//	glog.V(0).Infof("AkPub %v", akPubBytes)

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
