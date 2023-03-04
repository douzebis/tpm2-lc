// SPDX-License-Identifier: Apache-2.0

package teepeem

import (
	"io"

	"github.com/golang/glog"
	"github.com/google/go-tpm/tpm2"
)

// ### Clear TPM (on Attestor) #################################################

func Clear(rwc io.ReadWriter) {
	err := tpm2.Clear(
		rwc,
		tpm2.HandleLockout,
		tpm2.AuthCommand{
			Session:    tpm2.HandlePasswordSession,
			Attributes: tpm2.AttrContinueSession,
			// See https://github.com/google/go-tpm/issues/157
			Auth: make([]byte, 20), // The empty password
		},
	)
	if err != nil {
		glog.Fatalf("tpm2.Clear() failed: %v", err)
	}
}
