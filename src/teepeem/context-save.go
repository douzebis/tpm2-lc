// SPDX-License-Identifier: Apache-2.0

package teepeem

import (
	"encoding/hex"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"main/src/lib"
)

// === Save TPM context ========================================================

func ContextSave(
	rw io.ReadWriter,
	handle tpmutil.Handle,
) []byte {

	ekCtx, err := tpm2.ContextSave(rw, handle)
	if err != nil {
		lib.Fatal("tpm2.ContextSave() failed: %v", err)
	}
	lib.Verbose("tpm2.ContextSave() returned 0x%s", hex.EncodeToString(ekCtx))

	return ekCtx
}
