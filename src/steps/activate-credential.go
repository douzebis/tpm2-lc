// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"io"
	"io/ioutil"
	"log"

	"github.com/golang/glog"
	"github.com/google/go-tpm/tpm2"
)

// ### ActivateCredential (on attestor) ########################################

func ActivateCredential(rwc io.ReadWriter) {

	credBlob, err := ioutil.ReadFile("Verifier/credBlob")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for credBlob: %v", err)
	}
	glog.V(0).Infof("Read Verifier/credBlob")

	encSecret, err := ioutil.ReadFile("Verifier/encSecret")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for encSecret: %v", err)
	}
	glog.V(0).Infof("Read Verifier/encSecret")

	ekCtx, err := ioutil.ReadFile("Attestor/ek.ctx")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for EK Ctx: %v", err)
	}
	glog.V(0).Infof("Read Attestor/ek.ctx")

	ek, err := tpm2.ContextLoad(rwc, ekCtx)
	if err != nil {
		glog.Fatalf("tpm2.ContextLoad() failed for EK: %v", err)
	}
	defer tpm2.FlushContext(rwc, ek)

	loadSession, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256,
	)
	if err != nil {
		glog.Fatalf("tpm2.StartAuthSession() failed: %v", err)
	}
	defer tpm2.FlushContext(rwc, loadSession)

	_, _, err = tpm2.PolicySecret(
		rwc,
		tpm2.HandleEndorsement,
		tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
		loadSession,
		nil,
		nil,
		nil,
		0,
	)
	if err != nil {
		glog.Fatalf("tpm2.PolicySecret() failed: %v", err)
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadSession, Attributes: tpm2.AttrContinueSession}

	akPub, err := ioutil.ReadFile("Attestor/ak.pub.blob")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for ak.pub.blob: %v", err)
	}

	akPriv, err := ioutil.ReadFile("Attestor/ak.key.blob")
	if err != nil {
		glog.Fatalf("ioutil.ReadFile() failed for ak.key.blob: %v", err)
	}

	ak, _, err := tpm2.LoadUsingAuth(rwc, ek, authCommandLoad, akPub, akPriv)
	if err != nil {
		glog.Fatalf("tpm2.LoadUsingAuth() failed: %v", err)
	}
	defer tpm2.FlushContext(rwc, ak)

	err = tpm2.FlushContext(rwc, loadSession)
	if err != nil {
		glog.Fatalf("tpm2.FlushContext() failed: %v", err)
	}

	session, _, err := tpm2.StartAuthSession(rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("tpm2.StartAuthSession: %v", err)
	}

	auth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	_, _, err = tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, auth, session, nil, nil, nil, 0)
	if err != nil {
		glog.Fatalf("tpm2.AuthCommand: %v", err)
	}

	auths := []tpm2.AuthCommand{auth, {Session: session, Attributes: tpm2.AttrContinueSession}}
	out, err := tpm2.ActivateCredentialUsingAuth(rwc, auths, ak, ek, credBlob[2:], encSecret[2:])
	if err != nil {
		log.Fatalf("activate credential: %v", err)
	}

	err = ioutil.WriteFile("Attestor/secret", out, 0644)
	if err != nil {
		glog.Fatalf("ioutil.WriteFile() failed for Attestor/secret: %v", err)
	}
	glog.V(0).Infof("Wrote Attestor/secret")

}
