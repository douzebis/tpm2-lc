// SPDX-License-Identifier: Apache-2.0

package lib

import (
	"fmt"
	"io/fs"
	"io/ioutil"

	"github.com/golang/glog"
)

const (
	// See https://pkg.go.dev/github.com/ccpaging/nxlog4go@v2.0.3+incompatible/console#section-readme
	RED    = "\033[0;31m"
	GREEN  = "\033[0;32m"
	ORANGE = "\033[0;33m"
	RESET  = "\033[0m" // No Color
)

func Fatal(format string, params ...interface{}) {
	message := fmt.Sprintf(format, params...)
	glog.Fatalf("%s%s%s", RED, message, RESET)
}

func PRINT(format string, params ...interface{}) {
	message := fmt.Sprintf(format, params...)
	glog.V(0).Infof("%s%s%s", RED, message, RESET)
}

func Print(format string, params ...interface{}) {
	message := fmt.Sprintf(format, params...)
	glog.V(0).Infof("%s%s%s", GREEN, message, RESET)
}

func Comment(format string, params ...interface{}) {
	message := fmt.Sprintf(format, params...)
	glog.V(5).Infof("%s%s%s", ORANGE, message, RESET)
}

func Read(
	path string,
) (
	data []byte,
) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		Fatal("ioutil.ReadFile() failed: %v", err)
	}

	Comment("Read %s", path)

	return data
}

func Write(
	path string,
	data []byte,
	perm fs.FileMode,
) {
	err := ioutil.WriteFile(path, data, 0644)
	if err != nil {
		Fatal("ioutil.WriteFile() failed: %v", err)
	}
	Comment("Wrote %s", path)
}
