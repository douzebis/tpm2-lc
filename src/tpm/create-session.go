// SPDX-License-Identifier: Apache-2.0

package tpm

import (
	"encoding/hex"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"main/src/lib"
)

// === Retrieve PCRs values ====================================================

func CreateSession(
	rwc io.ReadWriter,
	sessionType tpmutil.Handle,
) tpmutil.Handle {

	// --- Start auth session for creating AK ----------------------------------
	// (Auth sessions are required for EK children)
	session, nonce, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,    // tpmKey
		tpm2.HandleNull,    // bindKey
		make([]byte, 16),   // nonceCaller
		nil,                // secret
		tpm2.SessionPolicy, // sessionType
		tpm2.AlgNull,       // sym algorithm
		tpm2.AlgSHA256,     // hash algorithm
	)
	if err != nil {
		lib.Fatal("tpm2.StartAuthSession() failed: %v", err)
	}
	//defer tpm2.FlushContext(rwc, createSession)
	lib.Verbose("session: 0x%08x", session)
	lib.Verbose("nonce: 0x%s", hex.EncodeToString(nonce))

	_, _, err = tpm2.PolicySecret(
		rwc,
		tpm2.HandleEndorsement, // entityHandle
		tpm2.AuthCommand{
			Session:    sessionType,
			Attributes: tpm2.AttrContinueSession,
		}, // entityAuth
		session, // sessionHandle
		nil,     // policyNonce
		nil,     // cpHash
		nil,     // policyRef
		0,       // expiry
	)
	if err != nil {
		lib.Fatal("tpm2.PolicySecret() failed for create session: %v", err)
	}

	return session
}
