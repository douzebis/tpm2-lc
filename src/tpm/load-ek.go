// SPDX-License-Identifier: Apache-2.0

package tpm

import (
	"io"

	"github.com/google/go-tpm/tpmutil"

	"main/src/lib"
)

// === Load AK (on Attestor) ===================================================

func LoadEK(
	rw io.ReadWriter, // IN
	attestorEkPath string, // IN
) (
	ek tpmutil.Handle,
) {

	ekCtx := lib.Read(attestorEkPath)
	ek = ContextLoad(rw, ekCtx)
	//defer tpm2.FlushContext(rw, ek)
	return ek
}
