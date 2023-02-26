// SPDX-License-Identifier: Apache-2.0

package tpm

import (
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/golang/glog"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// === Load AK (on Attestor) ===================================================

func LoadAK(
	rwc io.ReadWriter, // IN
	attestorEkPath string, // IN
	attestorAkPath string, // IN
) (
	ak tpmutil.Handle,
	akName []byte,
) {

	glog.V(10).Infof("     ContextLoad (ek) ========")
	ekhBytes, err := ioutil.ReadFile(ekFile)
	if err != nil {
		glog.Errorf("ERROR:   ContextLoad failed for ekh: %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekh file: %v", err))
	}
	ekh, err := tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		glog.Errorf("ERROR:   ContextLoad failed for ekhBytes: %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekhBytes: %v", err))
	}
	defer tpm2.FlushContext(rwc, ekh)
	glog.V(10).Infof("     LoadUsingAuth ========")

	loadCreateHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		glog.Errorf("ERROR:   Unable to create StartAuthSession : %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
		glog.Errorf("ERROR:   Unable to create PolicySecret : %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}

	glog.V(10).Infof("     Read (akPub) ========")
	akPub, err := ioutil.ReadFile(akPubFile)
	if err != nil {
		glog.Errorf("ERROR:   Read failed for akPub file: %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Read failed for akPub file: %v", err))
	}
	glog.V(10).Infof("     Read (akPriv) ========")
	akPriv, err := ioutil.ReadFile(akPrivFile)
	if err != nil {
		glog.Errorf("ERROR:   Read failed for akPriv file: %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Read failed for akPriv file: %v", err))
	}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		glog.Errorf("ERROR:   LoadUsingAuth failed for ak: %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("LoadUsingAuth failed for AK: %s", err))
	}
	defer tpm2.FlushContext(rwc, keyHandle)
	kn := hex.EncodeToString(keyName)
	glog.V(10).Infof("     AK keyName %s", kn)

	return ak, akName
}
