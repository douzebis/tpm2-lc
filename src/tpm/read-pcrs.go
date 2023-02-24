// SPDX-License-Identifier: Apache-2.0

package tpm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/golang/glog"
	"github.com/google/go-tpm/tpm2"

	"main/src/lib"
)

// === Retrieve PCRs values ====================================================

func ReadPCRs(
	rwc io.ReadWriter,
	pcrsList []int,
	filePrefix string,
) [32]byte {

	pcrsExpected := make([][]byte, len(pcrsList))
	pcrsConcat := []byte{}
	for ndx, val := range pcrsList {
		pcr, err := tpm2.ReadPCR(rwc, val, tpm2.AlgSHA384)
		if err != nil {
			glog.Fatalf("ERROR:   Unable to  ReadPCR : %v", err)
		}
		lib.Comment("PCR [%d] Value %v ", ndx, hex.EncodeToString(pcr))
		err = ioutil.WriteFile(fmt.Sprintf("%s-%d.bin", filePrefix, ndx),
			pcr, 0644)
		if err != nil {
			lib.Fatal("ioutil.WriteFile() failed: %v", err)
		}
		pcrsExpected[ndx] = pcr
		pcrsConcat = append(pcrsConcat, pcr...)
	}
	pcrsDigest := sha256.Sum256(pcrsConcat)
	lib.Comment("PCRs digest %s ", hex.EncodeToString(pcrsDigest[:]))

	err := ioutil.WriteFile(filePrefix+"-digest.bin",
		pcrsDigest[:], 0644)
	if err != nil {
		lib.Fatal("ioutil.WriteFile() failed: %v", err)
	}

	return pcrsDigest
}
