// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto"
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
	"github.com/google/go-tpm/tpmutil"
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

// ### CreateAK (on attestor) ##################################################

func CreateAK(rwc io.ReadWriter) {

	// === Load EK =============================================================

	ek, ekPublicKeyCrypto, err := CreateEK(rwc)
	if err != nil {
		glog.Fatalf("tpm2.CreatePrimary() failed for EK: %v", err)
	}
	defer tpm2.FlushContext(rwc, ek)
	glog.V(5).Infof("ek: 0x%08x", ek)
	glog.V(5).Infof("ekPublicKey : %v", ekPublicKeyCrypto)

	// === Save and reload EK context ==========================================

	ekCtx, err := tpm2.ContextSave(rwc, ek)
	if err != nil {
		glog.Fatalf("tpm2.ContextSave() failed for EK: %v", err)
	}
	glog.V(5).Infof("ekCtx 0x%s", hex.EncodeToString(ekCtx))

	err = ioutil.WriteFile("Attestor/ek.ctx", ekCtx, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed for EK Ctx: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/ek.ctx")

	err = tpm2.FlushContext(rwc, ek)
	if err != nil {
		glog.Fatalf("tpm2.FlushContext() failed: %v", err)
	}

	ekCtx, err = ioutil.ReadFile("Attestor/ek.ctx")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for Attestor/ek.ctx: %v", err)
	}

	ek, err = tpm2.ContextLoad(rwc, ekCtx)
	if err != nil {
		glog.Fatalf("tpm2.ContextLoad() failed for EK: %v", err)
	}
	glog.V(5).Infof("ek: 0x%08x", ek)

	defer tpm2.FlushContext(rwc, ek)

	//	ekPublicKey, ekName, ekQualName, err := tpm2.ReadPublic(rwc, ek)
	//	if err != nil {
	//		glog.Fatalf("tpm2.ReadPublic() failed for EK: %v", err)
	//	}
	//	glog.V(5).Infof("ekPublicKeyTpm2: %v", ekPublicKey)
	//	glog.V(5).Infof("ekName:     0x%s", hex.EncodeToString(ekName))
	//	glog.V(5).Infof("ekQualName: 0x%s", hex.EncodeToString(ekQualName))
	//
	//	ekPublicKeyCrypto2, err := ekPublicKey.Key()
	//	if err != nil {
	//		glog.Fatalf("ekPublic.Key() failed: %v", err)
	//	}
	//	glog.V(5).Infof("ekPublicKeyCrypto2: %v", ekPublicKeyCrypto2)

	ekPublicKeyDER, err := x509.MarshalPKIXPublicKey(ekPublicKeyCrypto)
	if err != nil {
		glog.Fatalf("x509.MarshalPKIXPublicKey() failed for EK Pub: %v", err)
	}
	glog.V(5).Infof("ekPublicKeyDER: 0x%s", hex.EncodeToString(ekPublicKeyDER))

	ekPublicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekPublicKeyDER,
		},
	)
	glog.V(5).Infof("ekPublicKeyPem: %s", string(ekPublicKeyPem))

	err = ioutil.WriteFile("Attestor/ek.pub", ekPublicKeyPem, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed for ek.pub: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/ek.pub")

	//	ekPublicKeyTPM, err := ekPublicKey.Encode()
	//	if err != nil {
	//		glog.Fatalf("tpmEkPub.Encode() failed: %v", err)
	//	}
	//	glog.V(5).Infof("ekPublicKeyTPM: 0x%s", hex.EncodeToString(ekPublicKeyTPM))

	// === Start auth session for AK creation ==================================

	// Auth sessions are required for EK children

	createSession, createSessionNonce, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("tpm2.StartAuthSession() failed: %v", err)
	}
	glog.V(5).Infof("createSession: 0x%08x", createSession)
	glog.V(5).Infof("createSessionNonce: 0x%s", hex.EncodeToString(createSessionNonce))

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

	akPrivateBlob, akPublicBlob, creationData, creationHash, creationTicket, err := tpm2.CreateKeyUsingAuth(
		rwc,
		ek,
		tpm2.PCRSelection{},
		authCommandCreateAuth,
		"",
		client.AKTemplateRSA(),
	)
	if err != nil {
		glog.Fatalf("tpm2.CreateKeyUsingAuth() failed: %v", err)
	}
	glog.V(5).Infof("akPrivateBlob 0x%s", hex.EncodeToString(akPrivateBlob))
	glog.V(5).Infof("akPublicBlob 0x%s", hex.EncodeToString(akPublicBlob))
	cr, err := tpm2.DecodeCreationData(creationData)
	if err != nil {
		glog.Fatalf("tpm2.DecodeCreationData() failed: %v", err)
	}
	glog.V(5).Infof("CredentialData.ParentName.Digest.Value 0x%s", hex.EncodeToString(cr.ParentName.Digest.Value))
	glog.V(5).Infof("CredentialHash 0x%s", hex.EncodeToString(creationHash))
	glog.V(5).Infof("CredentialTicket 0x%s", hex.EncodeToString(creationTicket.Digest))

	akPublicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akPublicBlob,
		},
	)
	glog.V(5).Infof("akPublicKeyPEM: %v", string(akPublicKeyPEM))

	err = tpm2.FlushContext(rwc, createSession)
	if err != nil {
		glog.Fatalf("tpm2.FlushContext() failed: %v", err)
	}

	// === Start auth session for loading AK ===================================

	// /!\ Loading AK as child of EK requires an auth session

	loadSession, loadSessionNonce, err := tpm2.StartAuthSession(
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
	glog.V(5).Infof("createSession: 0x%08x", loadSession)
	glog.V(5).Infof("createSessionNonce: 0x%s", hex.EncodeToString(loadSessionNonce))

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

	ak, akName, err := tpm2.LoadUsingAuth(rwc, ek, authCommandLoad, akPublicBlob, akPrivateBlob)
	if err != nil {
		glog.Fatalf("tpm2.LoadUsingAuth() failed: %v", err)
	}
	glog.V(5).Infof("ak: 0x%08x", ak)
	// akName consists of 36 bytes:
	// 00 22: rest is 34 bytes (0x22)
	// 00 0b: Algorighm is SHA256
	// xx...: 32 bytes for key hash
	glog.V(5).Infof("akName     : 0x%s", hex.EncodeToString(akName))

	defer tpm2.FlushContext(rwc, ak)

	err = tpm2.FlushContext(rwc, loadSession)
	if err != nil {
		glog.Fatalf("tpm2.FlushContext() failed: %v", err)
	}

	//	akPublicKey, akName_, akQualName2, err := tpm2.ReadPublic(rwc, ak)
	//	if err != nil {
	//		glog.Fatalf("tpm2.ReadPublic() failed: %v", err)
	//	}
	//	glog.V(5).Infof("akPublicKey: %v", akPublicKey)
	//	// akName_ consists of 34 bytes only (size header is missing):
	//	// 00 0b: Algorighm is SHA256
	//	// xx...: 32 bytes for key hash
	//	glog.V(5).Infof("akName_    : 0x%s", hex.EncodeToString(akName_))
	//	glog.V(5).Infof("akQualName2: 0x%s", hex.EncodeToString(akQualName2))
	//
	//	akPublicKeyCrypto, err := akPublicKey.Key()
	//	if err != nil {
	//		glog.Fatalf("akTpmPublicKey.Key() failed: %v", err)
	//	}
	//	glog.V(5).Infof("akPublicKeyCrypto: %v", akPublicKeyCrypto)
	//
	//	akPublicKeyDER, err := x509.MarshalPKIXPublicKey(akPublicKeyCrypto)
	//	if err != nil {
	//		glog.Fatalf("x509.MarshalPKIXPublicKey() failed: %v", err)
	//	}
	//	glog.V(5).Infof("akPublicKeyDER: 0x%s", hex.EncodeToString(akPublicKeyDER))
	//
	//	akPublicKeyPEM_ := pem.EncodeToMemory(
	//		&pem.Block{
	//			Type:  "PUBLIC KEY",
	//			Bytes: akPublicKeyDER,
	//		},
	//	)
	//	glog.V(5).Infof("akPublicKeyPEM_: %v", string(akPublicKeyPEM_))
	//
	//	akPublicKeyTPM, err := akPublicKey.Encode()
	//	if err != nil {
	//		glog.Errorf("akPublicKey.Encode() faile: %v", err)
	//	}
	//	glog.V(5).Infof("akPublicKeyTPM: 0x%s", hex.EncodeToString(akPublicKeyTPM))
	//
	//	akPublicKey2, err := tpm2.DecodePublic(akPublicKeyTPM)
	//	if err != nil {
	//		glog.Fatalf("tpm2.DecodePublic() failed: %v", err)
	//	}
	//
	//	akPublicKeyCrypto2, err := akPublicKey2.Key()
	//	if err != nil {
	//		glog.Fatalf("akPub.Key() failed: %s", err)
	//	}
	//	glog.V(5).Infof("akPublicKeyCrypto2: %v", akPublicKeyCrypto2)
	//
	//	akPublicKeyDER2, err := x509.MarshalPKIXPublicKey(akPublicKeyCrypto2)
	//	if err != nil {
	//		glog.Fatalf("x509.MarshalPKIXPublicKey() failed: %v", err)
	//	}
	//	glog.V(0).Infof("akBytes: \n%v", hex.EncodeToString(akPublicKeyDER2))
	//
	//	akPublicKeyPEM2 := pem.EncodeToMemory(
	//		&pem.Block{
	//			Type:  "PUBLIC KEY",
	//			Bytes: akPublicKeyDER2,
	//		},
	//	)
	//	glog.V(5).Infof("akPublicKeyPEM2: %sv", string(akPublicKeyPEM2))
	//
	//	if akPublicKey2.MatchesTemplate(client.AKTemplateRSA()) {
	//		glog.V(10).Infof("AK parameter match default template")
	//	} else {
	//		glog.Fatalf("AK parameter does not match default template")
	//	}
	//	ak2, akName2, err := tpm2.LoadExternal(rwc, akPublicKey2, tpm2.Private{}, tpm2.HandleNull)
	//	if err != nil {
	//		glog.Fatalf("Error loadingExternal AK %v", err)
	//	}
	//	glog.V(0).Infof("ak2: 0x%08x", ak2)
	//	glog.V(0).Infof("akName2: 0x%s", hex.EncodeToString(akName2))
	//
	//	defer tpm2.FlushContext(rwc, ak2)

	err = ioutil.WriteFile("Attestor/ak.pub", akPublicKeyPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/ak.pub")

	err = ioutil.WriteFile("Attestor/ak.key", akPrivateBlob, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/ak.key")

	err = ioutil.WriteFile("Attestor/ak.name", akName, 0644)
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
	glog.V(5).Infof("akName: 0x%s", hex.EncodeToString(akName))

	akPublicKeyPEM, err := ioutil.ReadFile("Attestor/ak.pub")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for Attestor/ak.pub: %v", err)
	}
	glog.V(5).Infof("akPubPEM: %s", string(akPublicKeyPEM))

	akBlock, _ := pem.Decode(akPublicKeyPEM)
	//akPub, err := x509.ParsePKIXPublicKey(akBlock.Bytes)
	//if err != nil {
	//	glog.Fatalf("x509.ParsePKCS1PrivateKey() failed: %v", err)
	//}
	akPublicKeyDER := akBlock.Bytes
	glog.V(0).Infof("akPub2: \n%v", hex.EncodeToString(akPublicKeyDER))

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

	hash, err := name.Digest.Alg.Hash()
	if err != nil {
		glog.Fatalf("failed to get name hash: %v", err)
	}

	pubHash := hash.New()
	pubHash.Write(akPublicKeyDER)
	pubDigest := pubHash.Sum(nil)
	if !bytes.Equal(name.Digest.Value, pubDigest) {
		glog.Fatalf("name was not for public blob")
	}

	// Inspect key attributes.
	pub, err := tpm2.DecodePublic(akPublicKeyDER)
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

// ### ActivateCredential (on attestor) ########################################

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

	akPubPem, err := ioutil.ReadFile("Attestor/ak.pub")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for ak.pub: %v", err)
	}
	akBlock, _ := pem.Decode(akPubPem)
	akPub := akBlock.Bytes

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
