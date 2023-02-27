// SPDX-License-Identifier: Apache-2.0

package teepeem

import (
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"main/src/lib"
)

// === Load TPM context ========================================================

func ContextLoad(
	rw io.ReadWriter,
	saveArea []byte,
) tpmutil.Handle {

	ek, err := tpm2.ContextLoad(rw, saveArea)
	if err != nil {
		lib.Fatal("tpm2.ContextLoad() failed: %v", err)
	}
	lib.Verbose("tpm2.ContextLoad() returned ùv", ek)

	return ek
}
