// SPDX-License-Identifier: Apache-2.0

package lib

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/golang/glog"
)

// This func must be Exported, Capitalized, and comment added.
func Parse(rest []byte, indent string) {
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, _ = asn1.Unmarshal(rest, &v)
		glog.V(0).Infof("%sClass %d", indent, v.Class)
		glog.V(0).Infof("%sTag %d", indent, v.Tag)
		glog.V(0).Infof("%sIsCompound %v", indent, v.IsCompound)
		glog.V(0).Infof("%sBytes %s", indent, string(v.FullBytes))
		glog.V(0).Infof("%sBytes %s", indent, base64.StdEncoding.EncodeToString(v.Bytes))
		glog.V(0).Infof("%sBytes %v", indent, v.Bytes)
		if v.IsCompound {
			parse(v.Bytes, indent+"  ")
		}
	}
}

// This func must be Exported, Capitalized, and comment added.
func CreateCA(name, path string) (*x509.Certificate, *rsa.PrivateKey) {

	// --- Create RSA key for TPM CA -------------------------------------------

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		glog.Fatalf("rsa.GenerateKey() failed: %v", err)
	}

	caPrivKeyPEM := []byte(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
		},
	))

	err = ioutil.WriteFile(path+".key", caPrivKeyPEM, 0600)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}

	glog.V(0).Infof("Wrote %s.key", path)

	// --- Create Certificate for TPM CA ---------------------------------------

	// From https://gist.github.com/op-ct/e202fc911de22c018effdb3371e8335f
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{name},
			OrganizationalUnit: []string{name + " Root CA"},
			CommonName:         name + " Root CA",
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
		&caTemplate,
		&caTemplate,
		&caPrivKey.PublicKey,
		caPrivKey)
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

	err = ioutil.WriteFile("TPM-CA/tpm-ca.crt", caPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}

	glog.V(0).Infof("Wrote TPM-CA/tpm-ca.crt")

	// --- Verify TPM CA cert --------------------------------------------------

	// Note: equivalently with openssl:
	// openssl verify -CAfile TPM-CA/tpm-ca.crt TPM-CA/tpm-ca.crt
	// openssl rsa -in TPM-CA/tpm-ca.key -pubout
	// openssl x509 -in TPM-CA/tpm-ca.crt -pubkey -noout

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		glog.Fatalf("x509.ParseCertificate() failed: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := caCert.Verify(opts); err != nil {
		glog.Fatalf("caCert.Verify() failed: %v", err)
	} else {
		glog.V(0).Infof("Verified %s", "TPM-CA/tpm-ca.crt")
	}

	return caCert, caPrivKey
}
