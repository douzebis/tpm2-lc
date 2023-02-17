// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"

	//	"strconv"
	//	"strings"
	//
	//	"crypto/x509"
	//	"encoding/hex"
	//	"encoding/pem"
	//	"io/ioutil"
	//
	//	"github.com/golang/protobuf/proto"
	//
	//	//"github.com/gogo/protobuf/proto"
	//	"github.com/golang/glog"
	//	"github.com/google/go-tpm-tools/client"
	//
	//	pb "github.com/google/go-tpm-tools/proto/tpm"
	//	"github.com/google/go-tpm-tools/server"
	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
)

var handleNames = map[string][]tpm2.HandleType{
	"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
	"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
	"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
	"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
}

var (
	//	mode           = flag.String("mode", "", "seal,unseal")
	tpmPath = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	// ekPubFile      = flag.String("ekPubFile", "", "ekPub file in PEM format")
	// sealedDataFile = flag.String("sealedDataFile", "", "sealedDataFile file")
	// secret         = flag.String("secret", "meet me at...", "secret")
	// pcrsValues     = flag.String("pcrValues", "", "SHA256 PCR Values to seal against 23=foo,20=bar.")
	// pcrMap         = map[uint32][]byte{}
	flush = flag.String("flush", "all", "Flush contexts, must be oneof transient|saved|loaded|all")
)

func main() {
	flag.Parse()

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

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		glog.Fatalf("Unable to load SRK from TPM: %v", err)
	}

	kPublicKey, _, _, err := tpm2.ReadPublic(rwc, ek.Handle())
	if err != nil {
		glog.Fatalf("Error tpmEkPub.Key() failed: %s", err)
	}

	ap, err := kPublicKey.Key()
	if err != nil {
		glog.Fatalf("reading Key() failed: %s", err)
	}
	akBytes, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		glog.Fatalf("Unable to convert ekpub: %v", err)
	}

	rakPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)
	glog.V(10).Infof("     akPubPEM: \n%v", string(rakPubPEM))

}
