// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"main/src/lib"
)

// === Verifier: generate quote request ========================================

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
	lib.Verbose("Quote nonce: 0x%s", hex.EncodeToString(nonce))

	// Write nonce to disk
	lib.Write(fmt.Sprintf("%s.bin", quoteNoncePath), nonce, 0600)

}
