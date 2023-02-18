// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
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

func parse(rest []byte, indent string) {
	//glog.V(10).Infof("%s", string(values))
	//glog.V(10).Infof("%sValueslen %d", indent, len(rest))
	//var seq asn1.RawValue
	//rest, _ := asn1.Unmarshal(values, &seq)
	//rest := seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		//glog.V(10).Infof("%sLen1 %d", indent, len(rest))
		//glog.V(10).Infof("%sRest1 %s", indent, string(rest))
		rest, _ = asn1.Unmarshal(rest, &v)
		//glog.V(10).Infof("%sLen2 %d", indent, len(rest))
		//glog.V(10).Infof("%sv.Bytes %d", indent, len(v.Bytes))
		//glog.V(10).Infof("%sRest2 %s", indent, string(rest))
		glog.V(10).Infof("%sClass %d", indent, v.Class)
		glog.V(10).Infof("%sTag %d", indent, v.Tag)
		glog.V(10).Infof("%sIsCompound %v", indent, v.IsCompound)
		glog.V(10).Infof("%sBytes %s", indent, string(v.FullBytes))
		glog.V(10).Infof("%sBytes %s", indent, base64.StdEncoding.EncodeToString(v.FullBytes))
		if v.IsCompound {
			//nextv := make([]byte, len(v.Bytes))
			//copy(nextv, v.Bytes)
			parse(v.Bytes, indent+"  ")
		} else {
			//glog.V(10).Infof("%sFullBytes %s", indent, string(v.FullBytes))
		}
	}
}

func main() {
	flag.Parse()

	testPem, err := ioutil.ReadFile("../tpm2/manufacturer/ek.crt")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed: %v", err)
	}
	block, _ := pem.Decode([]byte(testPem))
	if block == nil {
		glog.Fatalf("pem.Decode() failed: %v", err)
	}

	if block.Type == "CERTIFICATE" {
		glog.V(10).Infof("Block has type CERTIFICATE")
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			glog.Fatalf("x509.ParseCertificate() failed: %v", err)
		}
		for _, ext := range certificate.Extensions {
			// filter the custom extensions by customOID
			glog.V(10).Infof("extension %s", ext.Id.String())
			if ext.Id.String() == "2.5.29.17" {
				parse(ext.Value, "")
				//				return
				//				glog.V(10).Infof("Critical %s", ext.Critical)
				//				glog.V(10).Infof("Value %s", base64.StdEncoding.EncodeToString(ext.Value))
				//				//var oid asn1.ObjectIdentifier
				//				//asn1.Unmarshal(ext.Value, &oid)
				//				//glog.V(10).Infof("Oid %v", oid)
				//				//for _, tmp := range oid {
				//				//	glog.V(10).Infof("Oid %d", tmp)
				//				//}
				//				var seq asn1.RawValue
				//				asn1.Unmarshal(ext.Value, &seq)
				//				rest := seq.Bytes
				//				for len(rest) > 0 {
				//					var v asn1.RawValue
				//					rest, _ = asn1.Unmarshal(rest, &v)
				//					glog.V(10).Infof("Class %d", v.Class)
				//					glog.V(10).Infof("Tag %d", v.Tag)
				//					glog.V(10).Infof("IsCompound %v", v.IsCompound)
				//					glog.V(10).Infof("Bytes %s", string(v.Bytes))
				//					glog.V(10).Infof("FullBytes %s", string(v.FullBytes))
				//
				//					var toto asn1.RawValue
				//					asn1.Unmarshal(v.Bytes, &toto)
				//					titi := toto.Bytes
				//					for len(titi) > 0 {
				//						var tutu asn1.RawValue
				//						titi, _ = asn1.Unmarshal(titi, &tutu)
				//						glog.V(10).Infof("class %d", tutu.Class)
				//						glog.V(10).Infof("tag %d", tutu.Tag)
				//						glog.V(10).Infof("isCompound %v", tutu.IsCompound)
				//						glog.V(10).Infof("bytes %s", string(tutu.Bytes))
				//						glog.V(10).Infof("fullBytes %s", string(tutu.FullBytes))
				//
				//						var ante asn1.RawValue
				//						asn1.Unmarshal(toto.Bytes, &ante)
				//						rest2 := ante.Bytes
				//						for len(rest2) > 0 {
				//							var leaf asn1.RawValue
				//							rest2, _ = asn1.Unmarshal(rest2, &leaf)
				//							glog.V(10).Infof("class %d", leaf.Class)
				//							glog.V(10).Infof("tag %d", leaf.Tag)
				//							glog.V(10).Infof("isCompound %v", leaf.IsCompound)
				//							glog.V(10).Infof("bytes %s", string(leaf.Bytes))
				//							glog.V(10).Infof("fullBytes %s", string(leaf.FullBytes))
				//						}
				//
				//					}
				//				}
				//
			}
		}
	} else {
		glog.V(10).Infof("Block has type %s", block.Type)
	}

	// === Create certificate for TPM CA =======================================

	// Inspired by:
	// https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251
	// https://stackoverflow.com/a/70261780

	// --- Create RSA key for TPM CA -------------------------------------------

	tpmCaPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
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

	// From https://gist.github.com/op-ct/e202fc911de22c018effdb3371e8335f
	tpmCaTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{"TPM Manufacturer"},
			OrganizationalUnit: []string{"TPM Manufacturer Root CA"},
			CommonName:         "TPM Manufacturer Root CA",
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

	err = ioutil.WriteFile("TPM-CA/tpm-ca.crt", caPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}

	glog.V(10).Infof("Wrote TPM-CA/tpm-ca.crt")

	// Note: to check everything went OK on the target
	// openssl verify -CAfile TPM-CA/tpm-ca.crt TPM-CA/tpm-ca.crt
	// openssl rsa -in TPM-CA/tpm-ca.key -pubout
	// openssl x509 -in TPM-CA/tpm-ca.crt -pubkey -noout

	// === Create certificate for TPM ==========================================

	// --- Open TPM device -----------------------------------------------------

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("\ncan't close TPM %q: %v", tpmPath, err)
		}
	}()

	// --- Flush key handles ---------------------------------------------------

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

	// --- Retrieve TPM EK Pub -------------------------------------------------

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

	err = ioutil.WriteFile("TPM-CA/ek.pem", ekPubPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}

	glog.V(10).Infof("Wrote TPM-CA/ek.pem")

	switch ekPubKey.(type) {
	case *rsa.PublicKey:
		glog.V(10).Infof("ekPublicKey is of type RSA")
	}
	// From https://stackoverflow.com/a/44317246
	ekPublicKey, _ := ekPubKey.(*rsa.PublicKey)

	// --- Create TPM EK certificate -------------------------------------------

	// From https://gist.github.com/op-ct/e202fc911de22c018effdb3371e8335f
	//X509v3 extensions:
	//	X509v3 Subject Alternative Name: critical
	//		DirName:/2.23.133.2.2=id:%TPM_MODEL%+2.23.133.2.1=id:%TPM_MANUFACTURER%+2.23.133.2.3=id:%TPM_FIRMWARE_VERSION%
	//	X509v3 Basic Constraints: critical
	//		CA:FALSE
	//	X509v3 Key Usage:
	//		Key Encipherment
	//	X509v3 Subject Key Identifier:
	//		50:33:69:BA:1D:4A:D5:A1:AA:E9:E8:24:79:EB:78:0C:85:43:C0:96
	//	X509v3 Authority Key Identifier:
	//		59:46:B7:9A:1A:F8:8F:AE:53:01:22:1C:95:C5:9D:53:39:E8:11:EA
	//Signature Algorithm: sha256WithRSAEncryption
	//
	// See also https://upgrades.intel.com/content/CRL/ekcert/EKcertPolicyStatement.pdf
	extSubjectAltName := pkix.Extension{}
	extSubjectAltName.Id = asn1.ObjectIdentifier{2, 5, 29, 17}
	extSubjectAltName.Critical = false
	//extSubjectAltName.Value = []byte("DirName:/2.23.133.2.2=id:TPM_MODEL+2.23.133.2.1=id:TPM_MANUFACTURER+2.23.133.2.3=id:TPM_FIRMWARE_VERSION")
	extSubjectAltName.Value = []byte("")

	subjectAltName := asn1.ObjectIdentifier{2, 5, 29, 17}
	rawValues := []asn1.RawValue{
		{Class: 2, Tag: 6, Bytes: []byte("TPM_MODEL/1")},
		{Class: 2, Tag: 6, Bytes: []byte("TPM_MANUFACTURER/2")},
		{Class: 2, Tag: 6, Bytes: []byte("TPM_FIRMWARE_VERSION/3")},
	}
	values, err := asn1.Marshal(rawValues)
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	values, _ = base64.StdEncoding.DecodeString("MGOkYTBfMV0wFwYFZ4EFAgIMDmlkOiVUUE1fTU9ERUwlMB4GBWeBBQIBDBVpZDolVFBNX01BTlVGQUNUVVJFUiUwIgYFZ4EFAgMMGWlkOiVUUE1fRklSTVdBUkVfVkVSU0lPTiU=")

	//var buf []byte
	tpmFirmwareVersion := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagUTF8String,
		IsCompound: false,
		Bytes:      []byte("id:%TPM_FIRMWARE_VERSION%"),
	}
	//buf, err = asn1.Marshal("id:%TPM_FIRMWARE_VERSION%")
	//if err != nil {
	//	glog.Fatalf("asn1.Marshal() failed: %v", err)
	//}
	//tpmFirmwareVersion.Bytes = buf
	values, err = asn1.Marshal(tpmFirmwareVersion)
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}

	a, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 6, Bytes: []byte("g")})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	b, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 12, Bytes: []byte("id:%TPM_FIRMWARE_VERSION%")})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	c, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: append(a[:], b[:]...)})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	a2, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 6, Bytes: []byte("g")})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	b2, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 12, Bytes: []byte("id:%TPM_FIRMWARE_VERSION%")})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	c2, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: append(a2[:], b2[:]...)})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	d, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: append(c[:], c2[:]...)})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	e, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: d})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	f, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 4, IsCompound: true, Bytes: e})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	g, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: f})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	values = g

	tpmTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"TPM Inc"},
			CommonName:   "TPM",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		KeyUsage:  x509.KeyUsageKeyEncipherment,
		// Add subjectAltName
		//ExtraExtensions: []pkix.Extension{extSubjectAltName},
		ExtraExtensions: []pkix.Extension{{Id: subjectAltName, Critical: true, Value: values}},
		//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	tpmBytes, err := x509.CreateCertificate(
		rand.Reader,
		&tpmTemplate,
		&tpmCaTemplate,
		ekPublicKey,
		tpmCaPrivKey)
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

	err = ioutil.WriteFile("TPM-CA/tpm.crt", tpmPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}

	glog.V(10).Infof("Wrote TPM-CA/tpm.crt")

	// Note: to check everything went OK on the target
	// openssl verify -CAfile TPM-CA/tpm-ca.crt TPM-CA/tpm.crt

}
