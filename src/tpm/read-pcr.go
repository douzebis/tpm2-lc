// SPDX-License-Identifier: Apache-2.0

package tpm

import (
	"encoding/hex"
	"io"

	"github.com/google/go-tpm/tpm2"

	"main/src/lib"
)

// === Flush TPM context =======================================================

func ReadPCR(
	rw io.ReadWriter,
	pcr int,
) []byte {

	val, err := tpm2.ReadPCR(rw, pcr, tpm2.AlgSHA256)
	if err != nil {
		lib.Fatal("tpm2.ReadPCR() failed: %v", err)
	}
	lib.Comment("PCR[%d] == %v ", pcr, hex.EncodeToString(val))
	return val
}
