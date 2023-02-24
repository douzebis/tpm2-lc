// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"

	"github.com/golang/glog"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
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
