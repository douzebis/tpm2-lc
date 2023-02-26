// SPDX-License-Identifier: Apache-2.0

package tpm

import (
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"main/src/lib"
)

// === Flush TPM context =======================================================

func FlushContext(
	rw io.ReadWriter,
	handle tpmutil.Handle,
) {

	err := tpm2.FlushContext(rw, handle)
	if err != nil {
		lib.Fatal("tpm2.FlushContext() failed: %v", err)
	}
}
