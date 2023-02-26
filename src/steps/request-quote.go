// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"crypto/rand"
	"fmt"

	"main/src/lib"
)

// ### RequestQuote (on Verifier) ##############################################
func RequestQuote(
	quoteNoncePath string,
) {

	lib.PRINT("=== VERIFIER: GENERATE QUOTE REQUEST ===========================================")

	// Generate a nonce for the quote requestk challenge
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		lib.Fatal("rand.Read() failed: %v", err)
	}

	// Write nonce to disk
	lib.Write(fmt.Sprintf("%s.bin", quoteNoncePath), nonce, 0600)

}
