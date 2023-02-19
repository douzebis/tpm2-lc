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

func main() {
	flag.Parse()

	// --- Snippet: parse a certificate extensions -----------------------------

	//	testPem, err := ioutil.ReadFile("TPM-CA/tpm.crt")
	//	if err != nil {
	//		glog.Fatalf("ioutil.ReadFile() failed: %v", err)
	//	}
	//	block, _ := pem.Decode([]byte(testPem))
	//	if block == nil {
	//		glog.Fatalf("pem.Decode() failed: %v", err)
	//	}
	//
	//	if block.Type == "CERTIFICATE" {
	//		glog.V(0).Infof("Block has type CERTIFICATE")
	//		certificate, err := x509.ParseCertificate(block.Bytes)
	//		if err != nil {
	//			glog.Fatalf("x509.ParseCertificate() failed: %v", err)
	//		}
	//		for _, ext := range certificate.Extensions {
	//			// filter the custom extensions by customOID
	//			glog.V(0).Infof("extension %s", ext.Id.String())
	//			if ext.Id.String() == "2.5.29.17" {
	//				parse(ext.Value, "")
	//			}
	//		}
	//	} else {
	//		glog.V(0).Infof("Block has type %s", block.Type)
	//	}

	// Since GCP Shielded VMs TPM Endorsement Keys come without a proper
	// certificate, we fake a TPM CA and a fake TPM EK certificate.

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

	glog.V(0).Infof("Wrote TPM-CA/tpm-ca.key")

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

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		glog.Fatalf("x509.ParseCertificate() failed: %v", err)
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

	glog.V(0).Infof("Wrote TPM-CA/ek.pem")

	switch ekPubKey.(type) {
	case *rsa.PublicKey:
		glog.V(0).Infof("ekPublicKey is of type RSA")
	}
	// From https://stackoverflow.com/a/44317246
	ekPublicKey, _ := ekPubKey.(*rsa.PublicKey)

	// --- Create TPM EK certificate -------------------------------------------

	// See https://marc.info/?l=openssl-users&m=135119943225986&w=2
	// See also https://upgrades.intel.com/content/CRL/ekcert/EKcertPolicyStatement.pdf
	//
	// SEQUENCE {
	//   SEQUENCE {
	//     OBJECT IDENTIFIER subjectAltName (2 5 29 17)
	//        (X.509 extension)
	//     BOOLEAN TRUE
	//     OCTET STRING, encapsulates {
	//       SEQUENCE {
	//         [4] {
	//           SEQUENCE {
	//             SET {
	//               SEQUENCE {
	//                 OBJECT IDENTIFIER '2 23 133 2 1'
	//                 PrintableString 'id:57454300'
	//                  }
	//               SEQUENCE {
	//                 OBJECT IDENTIFIER '2 23 133 2 2'
	//                 PrintableString 'NPCT42x/NPCT50x'
	//                  }
	//               SEQUENCE {
	//                 OBJECT IDENTIFIER '2 23 133 2 3'
	//                 PrintableString 'id:0391'
	//                  }
	//                }
	//              }
	//            }
	//          }
	//        }
	//      }

	a1, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagOID,
		Bytes: []byte{103, 129, 5, 2, 1}, // ASN1 encoding for 2.23.133.2.1
	})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	b1, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagUTF8String,
		Bytes: []byte("id: Google"),
	})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	c1, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      append(a1[:], b1[:]...),
	})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	a2, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagOID,
		Bytes: []byte{103, 129, 5, 2, 2}, // ASN1 encoding for 2.23.133.2.2
	})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	b2, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagUTF8String,
		Bytes: []byte("id: Shielded VM vTPM"),
	})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	c2, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true, Bytes: append(a2[:], b2[:]...),
	})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	a3, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagOID,
		Bytes: []byte{103, 129, 5, 2, 3}, // ASN1 encoding for 2.23.133.2.3
	})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	b3, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagUTF8String,
		Bytes: []byte("id: 00010001"),
	})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	c3, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true, Bytes: append(a3[:], b3[:]...),
	})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	d, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      append(append(c1[:], c2[:]...), c3[:]...),
	})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	e, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      d,
	})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	f, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        asn1.TagOctetString,
		IsCompound: true,
		Bytes:      e,
	})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}
	values, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      f,
	})
	if err != nil {
		glog.Fatalf("asn1.Marshal() failed: %v", err)
	}

	tpmTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"TPM Inc"},
			CommonName:   "TPM",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		KeyUsage:  x509.KeyUsageKeyEncipherment,
		ExtraExtensions: []pkix.Extension{{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 17},
			Critical: true,
			Value:    values,
		}},
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

	glog.V(0).Infof("Wrote TPM-CA/tpm.crt")

	// --- Verify TPM cert -----------------------------------------------------

	// Note: equivalently with openssl:
	// openssl verify -CAfile TPM-CA/tpm-ca.crt TPM-CA/tpm.crt
	// openssl x509 -noout -ext subjectAltName -in TPM-CA/tpm.crt

	tpmCert, err := x509.ParseCertificate(tpmBytes)
	if err != nil {
		glog.Fatalf("x509.ParseCertificate() failed: %v", err)
	}
	glog.V(0).Infof("cert before %v", tpmCert)
	tpmCert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}
	glog.V(0).Infof("cert after %v", tpmCert)

	if _, err := tpmCert.Verify(opts); err != nil {
		glog.Fatalf("tpmCert.Verify() failed: %v", err)
	} else {
		glog.V(0).Infof("Verified %s", "TPM-CA/tpm.crt")
	}

	// === Create certificate for Owner CA =====================================

	// --- Create RSA key for Owner CA -----------------------------------------

	ownerCaPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		glog.Fatalf("rsa.GenerateKey() failed: %v", err)
	}

	ownerCaPrivKeyPEM := []byte(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(ownerCaPrivKey),
		},
	))

	err = ioutil.WriteFile("Owner-CA/owner-ca.key", ownerCaPrivKeyPEM, 0600)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}

	glog.V(0).Infof("Wrote Owner-CA/tpm-ca.key")

	// --- Create Certificate for TPM CA ---------------------------------------

	// From https://gist.github.com/op-ct/e202fc911de22c018effdb3371e8335f
	ownerCaTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{"TPM Owner"},
			OrganizationalUnit: []string{"TPM Owner Root CA"},
			CommonName:         "TPM Owner Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	ownerCaBytes, err := x509.CreateCertificate(
		rand.Reader,
		&ownerCaTemplate,
		&ownerCaTemplate,
		&ownerCaPrivKey.PublicKey,
		ownerCaPrivKey)
	if err != nil {
		glog.Fatalf("x509.CreateCertificate() failed: %v", err)
	}

	// pem encode
	ownerCaPEM := []byte(pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ownerCaBytes,
		},
	))

	err = ioutil.WriteFile("Owner-CA/owner-ca.crt", ownerCaPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}

	glog.V(0).Infof("Wrote Owner-CA/owner-ca.crt")

	// Note: to check everything went OK on the target
	// openssl verify -CAfile TPM-CA/tpm-ca.crt TPM-CA/tpm-ca.crt
	// openssl rsa -in TPM-CA/tpm-ca.key -pubout
	// openssl x509 -in TPM-CA/tpm-ca.crt -pubkey -noout

}
