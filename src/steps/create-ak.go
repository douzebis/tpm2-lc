// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"io/ioutil"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"

	"main/src/tpm"
)

// ### CreateAK (on attestor) ##################################################

func CreateAK(rwc io.ReadWriter) {

	// === Load EK =============================================================

	ek, ekPublicKeyCrypto, err := tpm.CreateEK(rwc)
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

	//akPublicKeyPEM := pem.EncodeToMemory(
	//	&pem.Block{
	//		Type:  "PUBLIC KEY",
	//		Bytes: akPublicBlob,
	//	},
	//)
	//glog.V(5).Infof("akPublicKeyPEM: %v", string(akPublicKeyPEM))

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
	// See https://github.com/tpm2-software/tpm2-tools/issues/1872
	glog.V(5).Infof("akName     : 0x%s", hex.EncodeToString(akName))

	defer tpm2.FlushContext(rwc, ak)

	err = tpm2.FlushContext(rwc, loadSession)
	if err != nil {
		glog.Fatalf("tpm2.FlushContext() failed: %v", err)
	}

	akPublicKey, akName_, akQualName_, err := tpm2.ReadPublic(rwc, ak)
	if err != nil {
		glog.Fatalf("tpm2.ReadPublic() failed: %v", err)
	}
	glog.V(5).Infof("akPublicKey: %v", akPublicKey)
	// akName_ consists of 34 bytes only (size header is missing):
	// 00 0b: Algorighm is SHA256
	// xx...: 32 bytes for key hash
	glog.V(5).Infof("akName_    : 0x%s", hex.EncodeToString(akName_))
	glog.V(5).Infof("akQualName2: 0x%s", hex.EncodeToString(akQualName_))

	akPublicKeyCrypto, err := akPublicKey.Key()
	if err != nil {
		glog.Fatalf("akTpmPublicKey.Key() failed: %v", err)
	}
	glog.V(5).Infof("akPublicKeyCrypto: %v", akPublicKeyCrypto)
	glog.V(5).Infof("akPublicKeyCrypto.Modulus: 0x%x", akPublicKeyCrypto.(*rsa.PublicKey).N)

	akPublicKeyDER, err := x509.MarshalPKIXPublicKey(akPublicKeyCrypto)
	if err != nil {
		glog.Fatalf("x509.MarshalPKIXPublicKey() failed: %v", err)
	}
	glog.V(5).Infof("akPublicKeyDER: 0x%s", hex.EncodeToString(akPublicKeyDER))

	akPublicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akPublicKeyDER,
		},
	)
	glog.V(5).Infof("akPublicKeyPEM_: %v", string(akPublicKeyPEM))

	err = ioutil.WriteFile("Attestor/ak.pub", akPublicKeyPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/ak.pub")

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

	err = ioutil.WriteFile("Attestor/ak.pub.blob", akPublicBlob, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/ak.pub.blob")

	err = ioutil.WriteFile("Attestor/ak.key.blob", akPrivateBlob, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/ak.key.blob")

	err = ioutil.WriteFile("Attestor/ak.name", akName, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed for ak.name: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/ak.name")
}
