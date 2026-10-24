//go:build !windows

package service

import (
	"errors"
)

const (
	ServiceName = "SinkholeDNS"
	DisplayName = "Sinkhole DNS Ad & Tracker Filter"
	Description = "Sinkhole DNS server"
)

func IsService() bool { return false }
func RunAsService(dataDir, version string) error {
	return errors.New("windows service is only supported on windows")
}
func Install(exePath, dataDir string) error {
	return errors.New("windows service is only supported on windows")
}
func Uninstall() error {
	return errors.New("windows service is only supported on windows")
}
func Start() error {
	return errors.New("windows service is only supported on windows")
}
func Stop() error {
	return errors.New("windows service is only supported on windows")
}
func Status() (string, error) {
	return "Unsupported", nil
}
