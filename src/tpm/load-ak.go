// SPDX-License-Identifier: Apache-2.0

package tpm

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"main/src/lib"
)

// === Load AK (on Attestor) ===================================================

func LoadAK(
	rw io.ReadWriter,
	ek tpmutil.Handle,
	attestorAkPath string, // IN
) (
	ak tpmutil.Handle,
	akName []byte,
) {

	// Read AK public and private blobs from disk
	akPublicBlob := lib.Read(fmt.Sprintf("%s-pub.blob", attestorAkPath))
	akPrivateBlob := lib.Read(fmt.Sprintf("%s-priv.blob", attestorAkPath))

	// Start auth session for loading AK
	session := CreateSession(
		rw,
		tpm2.HandlePasswordSession,
	)
	defer tpm2.FlushContext(rw, session)

	// Load AK
	ak, akName, err := tpm2.LoadUsingAuth(
		rw,
		ek, // parentHandle
		tpm2.AuthCommand{
			Session:    session,
			Attributes: tpm2.AttrContinueSession,
		}, // authCommand
		akPublicBlob,  // publicBlob
		akPrivateBlob, // privateBlob
	)
	if err != nil {
		lib.Fatal("tpm2.LoadUsingAuth() failed: %v", err)
	}
	lib.Verbose("ak: 0x%08x", ak)
	// akName consists of 36 bytes:
	// 00 22: rest is 34 bytes (0x22)
	// 00 0b: Algorighm is SHA256
	// xx...: 32 bytes for key hash
	// See https://github.com/tpm2-software/tpm2-tools/issues/1872
	lib.Verbose("akName: 0x%s", hex.EncodeToString(akName))

	return ak, akName
	// defer tpm2.FlushContext(rw, ak)
}

//	glog.V(10).Infof("     ContextLoad (ek) ========")
//	ekhBytes, err := ioutil.ReadFile(ekFile)
//	if err != nil {
//		glog.Errorf("ERROR:   ContextLoad failed for ekh: %v", err)
//		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekh file: %v", err))
//	}
//	ekh, err := tpm2.ContextLoad(rw, ekhBytes)
//	if err != nil {
//		glog.Errorf("ERROR:   ContextLoad failed for ekhBytes: %v", err)
//		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekhBytes: %v", err))
//	}
//	defer tpm2.FlushContext(rw, ekh)
//	glog.V(10).Infof("     LoadUsingAuth ========")
//
//	loadCreateHandle, _, err := tpm2.StartAuthSession(
//		rw,
//		tpm2.HandleNull,
//		tpm2.HandleNull,
//		make([]byte, 16),
//		nil,
//		tpm2.SessionPolicy,
//		tpm2.AlgNull,
//		tpm2.AlgSHA256)
//	if err != nil {
//		glog.Errorf("ERROR:   Unable to create StartAuthSession : %v", err)
//		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
//	}
//	defer tpm2.FlushContext(rw, loadCreateHandle)
//
//	if _, err := tpm2.PolicySecret(rw, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
//		glog.Errorf("ERROR:   Unable to create PolicySecret : %v", err)
//		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
//	}
//
//	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}
//
//	glog.V(10).Infof("     Read (akPub) ========")
//	akPub, err := ioutil.ReadFile(akPubFile)
//	if err != nil {
//		glog.Errorf("ERROR:   Read failed for akPub file: %v", err)
//		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Read failed for akPub file: %v", err))
//	}
//	glog.V(10).Infof("     Read (akPriv) ========")
//	akPriv, err := ioutil.ReadFile(akPrivFile)
//	if err != nil {
//		glog.Errorf("ERROR:   Read failed for akPriv file: %v", err)
//		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Read failed for akPriv file: %v", err))
//	}
//
//	keyHandle, keyName, err := tpm2.LoadUsingAuth(rw, ekh, authCommandLoad, akPub, akPriv)
//	if err != nil {
//		glog.Errorf("ERROR:   LoadUsingAuth failed for ak: %v", err)
//		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("LoadUsingAuth failed for AK: %s", err))
//	}
//	defer tpm2.FlushContext(rw, keyHandle)
//	kn := hex.EncodeToString(keyName)
//	glog.V(10).Infof("     AK keyName %s", kn)
