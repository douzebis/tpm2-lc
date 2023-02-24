// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"

	"main/src/lib"
)

// ### Attestor: activate credential ###########################################

func ActivateCredential(
	rwc io.ReadWriter, // IN
	verifierCredentialPath string, // IN
	attestorEkPath string, // IN
	attestorAkPath string, // IN
	attestorAttemptPath string, // OUT
) {

	lib.PRINT("=== ATTESTOR: ACTIVATE CREDENTIAL ==============================================")

	// Retrieve credential challenge TPM2B_ID_OBJECT
	idObject := lib.Read(fmt.Sprintf("%s-object.blob", verifierCredentialPath))

	// Retrieve credential challenge TPM2B_ENCRYPTED_SECRET
	encSecret := lib.Read(fmt.Sprintf("%s-secret.blob", verifierCredentialPath))

	// Retrieve EK ctx
	ekCtx := lib.Read(fmt.Sprintf("%s.ctx", attestorEkPath))

	// Load EK
	ek, err := tpm2.ContextLoad(rwc, ekCtx)
	if err != nil {
		lib.Fatal("tpm2.ContextLoad() failed for EK: %v", err)
	}
	defer tpm2.FlushContext(rwc, ek)

	// --- Start auth session for creating AK ----------------------------------
	// (Auth sessions are required for EK children)
	loadSession, _, err := tpm2.StartAuthSession(
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
	defer tpm2.FlushContext(rwc, loadSession)

	_, _, err = tpm2.PolicySecret(
		rwc,
		tpm2.HandleEndorsement, // entityHandle
		tpm2.AuthCommand{
			Session:    tpm2.HandlePasswordSession,
			Attributes: tpm2.AttrContinueSession,
		}, // entityAuth
		loadSession, // sessionHandle
		nil,         // policyNonce
		nil,         // cpHash
		nil,         // policyRef
		0,           // expiry
	)
	if err != nil {
		lib.Fatal("tpm2.PolicySecret() failed: %v", err)
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadSession, Attributes: tpm2.AttrContinueSession}

	// Retrieve AK Pub blob
	akPub := lib.Read(fmt.Sprintf("%s-pub.blob", attestorAkPath))

	// Retrieve AK Priv blob
	akPriv := lib.Read(fmt.Sprintf("%s-priv.blob", attestorAkPath))

	// Load AK
	ak, _, err := tpm2.LoadUsingAuth(
		rwc,
		ek,              // parentHandle
		authCommandLoad, // authCommand
		akPub,           // publicBlob
		akPriv,          // privateBlob
	)
	if err != nil {
		lib.Fatal("tpm2.LoadUsingAuth() failed: %v", err)
	}
	defer tpm2.FlushContext(rwc, ak)

	err = tpm2.FlushContext(rwc, loadSession)
	if err != nil {
		lib.Fatal("tpm2.FlushContext() failed: %v", err)
	}

	// --- Start auth session for activating credential ------------------------
	// (Auth sessions are required for EK children)
	session, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,    // tpmKey
		tpm2.HandleNull,    // bindKey
		make([]byte, 16),   // nonceCaller
		nil,                // secret
		tpm2.SessionPolicy, // sessionType
		tpm2.AlgNull,       // symmetric algorithm
		tpm2.AlgSHA256,     // hash algorithm
	)
	if err != nil {
		lib.Fatal("tpm2.StartAuthSession: %v", err)
	}

	auth := tpm2.AuthCommand{
		Session:    tpm2.HandlePasswordSession,
		Attributes: tpm2.AttrContinueSession,
	}

	_, _, err = tpm2.PolicySecret(
		rwc,
		tpm2.HandleEndorsement, // entityHandle
		auth,                   // authCommand
		session,                // policyHandle
		nil,                    // policyNonce
		nil,                    // cpHash
		nil,                    // policyRef
		0,                      // expiry
	)
	if err != nil {
		lib.Fatal("tpm2.AuthCommand: %v", err)
	}

	auths := []tpm2.AuthCommand{
		auth,
		{
			Session:    session,
			Attributes: tpm2.AttrContinueSession,
		},
	}

	// Activate credential
	attempt, err := tpm2.ActivateCredentialUsingAuth(
		rwc,
		auths,         // authCommands
		ak,            // activeHandle
		ek,            // keyHandle
		idObject[2:],  // idObject (skip length header)
		encSecret[2:], // encSecret (skip lenght header)
	)
	if err != nil {
		lib.Fatal("activate credential: %v", err)
	}

	lib.Write(fmt.Sprintf("%s.bin", attestorAttemptPath), attempt, 0644)
}
