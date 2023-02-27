// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/tpm"
	"google.golang.org/protobuf/proto"

	"main/src/lib"
)

// === Verifier: seal secret key ===============================================

func UnsealKey(
	rw io.ReadWriter,
	sealedKeyPath string, // IN
	attestorUnsealedKeyPath string, // OUT
) []byte {

	lib.PRINT("=== ATTESTOR: UNSEAL SECRET KEY ================================================")

	//srk := teepeem.LoadEK(
	//	rw,
	//	attestorSrkPath, // IN
	//)
	srkClient, err := client.StorageRootKeyRSA(rw)
	if err != nil {
		lib.Fatal("client.StorageRootKeyRSA() failed: %v", err)
	}

	blob := &tpm.ImportBlob{}
	sealedKey := lib.Read(fmt.Sprintf("%s.bin", sealedKeyPath))
	err = proto.Unmarshal(sealedKey, blob)
	if err != nil {
		lib.Fatal("proto.Unmarshal() failed: %v", err)
	}
	unsealedKey, err := srkClient.Import(blob)
	if err != nil {
		lib.Fatal("srkClient.Import() failed: %v", err)
	}
	lib.Print("Unsealed secret: %v", unsealedKey)

	return unsealedKey
}
