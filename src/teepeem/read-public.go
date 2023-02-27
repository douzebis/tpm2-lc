// SPDX-License-Identifier: Apache-2.0

package teepeem

import (
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"main/src/lib"
)

// === Save TPM context ========================================================

func ReadPublic(
	rw io.ReadWriter,
	handle tpmutil.Handle, // keyHandle
) (
	publicKey tpm2.Public,
	name []byte,
	qualName []byte,
) {

	publicKey, name, qualName, err := tpm2.ReadPublic(
		rw,
		handle,
	)
	if err != nil {
		lib.Fatal("tpm2.ReadPublic() failed: %v", err)
	}

	return publicKey, name, qualName
}
