// SPDX-License-Identifier: Apache-2.0

package certs

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
			Parse(v.Bytes, indent+"  ")
		}
	}
}

// This func must be Exported, Capitalized, and comment added.
func CreateCA(name, path string) (*x509.Certificate, *rsa.PrivateKey) {

	// Inspired by:
	// https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251
	// https://stackoverflow.com/a/70261780

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

	err = ioutil.WriteFile(path+".crt", caPEM, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed: %v", err)
	}

	glog.V(0).Infof("Wrote %s.crt", path)

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
		glog.V(0).Infof("Verified %s.crt", path)
	}

	return caCert, caPrivKey
}

// This func must be Exported, Capitalized, and comment added.
func CreateSubjectAltName(tpmManufacturer, tpmModel, tpmFirmwareVersion []byte) *pkix.Extension {

	// Inspired by:
	// https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251
	// https://stackoverflow.com/a/70261780

	// --- Create RSA key for TPM CA -------------------------------------------
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
		Bytes: tpmManufacturer,
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
		Bytes: tpmModel,
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
		Bytes: []byte(tpmFirmwareVersion),
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

	return &pkix.Extension{
		// {joint-iso-itu-t(2) ds(5) certificateExtension(29) subjectAltName(17)}
		Id:       asn1.ObjectIdentifier{2, 5, 29, 17},
		Critical: true,
		Value:    values,
	}
}
