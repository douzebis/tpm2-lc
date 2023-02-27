// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/tpm2"
	"google.golang.org/protobuf/proto"

	"main/src/certs"
	"main/src/lib"
)

// === Verifier: seal secret key ===============================================

func SealKey(
	aesKey [32]byte, // AES256 key
	verifierSrkPath string, // IN
	cicdDigestPath string, // IN
	cicdSealedKeyPath string, // OUT
) {

	lib.PRINT("=== CICD: SEAL SECRET KEY -=====================================================")

	// Read SRK public key from disk
	srkPublicKey := certs.ReadPublicKey(verifierSrkPath)
	lib.Verbose("srkPublicKey: %v", srkPublicKey)

	// Read expected PCRs digest from disk
	pcrDigest := lib.Read(fmt.Sprintf("%s.bin", cicdDigestPath))
	lib.Verbose("pcrDigest: %v", pcrDigest)

	// Retrieve events log
	eventsLog := lib.Read("CICD/cicd-prediction.bin")
	parsedEventsLog, err := attest.ParseEventLog(eventsLog)
	if err != nil {
		lib.Fatal("attest.ParseEventLog() failed: %v", err)
	}

	// Compute expected PCR values
	pcrs := [][32]byte{}
	for i := 0; i < 24; i++ {
		pcrs = append(pcrs, [32]byte{})
		//lib.Verbose("PCR[%2d]: %v", i, pcrs[i])
		//lib.Verbose("PCR[%2d]: 0x%s", i, hex.EncodeToString(pcrs[i][:]))
	}
	for _, e := range parsedEventsLog.Events(attest.HashAlg(tpm2.AlgSHA256)) {
		// sudo cat pcr.bin digest.bin | openssl dgst -sha256 -binary > futurepcr.bin
		i := e.Index
		pcrs[i] = sha256.Sum256(append(pcrs[i][:], e.Digest...))
		lib.Verbose("PCR[%2d]+0x%s => 0x%s", i,
			hex.EncodeToString(e.Digest), hex.EncodeToString(pcrs[i][:]))
	}

	// Prepare pcrMap for sealing
	pcrMap := make(map[uint32][]byte)
	for _, i := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 14} {
		pcrMap[uint32(i)] = pcrs[i][:]
	}
	lib.Verbose("pcrMap: %v", pcrMap)
	selectedPcrs := tpm.PCRs{
		Hash: tpm.HashAlgo_SHA256,
		Pcrs: pcrMap,
	}

	// Seal AES key
	sealedBlob, err := server.CreateImportBlob(
		&srkPublicKey, // crypto.PublicKey
		aesKey[:],     //[]byte
		&selectedPcrs, // *tpm.PCRs
	)
	if err != nil {
		lib.Fatal("server.CreateImportBlob() failed : %v", err)
	}

	// Write sealed AES key to disk
	sealedKey, err := proto.Marshal(sealedBlob)
	if err != nil {
		lib.Fatal("proto.Marshal() failed: %v", err)
	}
	lib.Write(fmt.Sprintf("%s.bin", cicdSealedKeyPath), sealedKey, 0644)
}
