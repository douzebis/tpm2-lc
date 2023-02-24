// SPDX-License-Identifier: Apache-2.0

package lib

import (
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
