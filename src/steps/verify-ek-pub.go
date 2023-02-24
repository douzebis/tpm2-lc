// SPDX-License-Identifier: Apache-2.0

package steps

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"time"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"

	"main/src/certs"
	"main/src/steps"
)

// ### Clear TPM (on Attestor) #################################################

func Clear(rwc io.ReadWriter) {
