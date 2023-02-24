// SPDX-License-Identifier: Apache-2.0

package lib

import (
	"io/fs"
	"io/ioutil"

	"github.com/golang/glog"
)

func Fatal(format string, params ...interface{}) {
	glog.Fatalf(format, params...)
}

func Print(format string, params ...interface{}) {
	glog.V(0).Infof(format, params...)
}

func Comment(format string, params ...interface{}) {
	glog.V(5).Infof(format, params...)
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
