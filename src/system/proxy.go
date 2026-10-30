//go:build windows

package system

import (
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

var (
	modwininet            = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOption = modwininet.NewProc("InternetSetOptionW")
)

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

// ProxyStatus describes current Windows proxy configuration.
type ProxyStatus struct {
	Enabled       bool   `json:"enabled"`
	Server        string `json:"server"`
	AutoConfigURL string `json:"auto_config_url"`
	Override      string `json:"override"`
}

// GetProxyStatus returns active Windows proxy settings from the registry.
func GetProxyStatus() (ProxyStatus, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return ProxyStatus{}, err
	}
	defer k.Close()

	var st ProxyStatus
	enabled, _, err := k.GetIntegerValue("ProxyEnable")
	if err == nil && enabled == 1 {
		st.Enabled = true
	}

	server, _, err := k.GetStringValue("ProxyServer")
	if err == nil {
		st.Server = server
	}

	pac, _, err := k.GetStringValue("AutoConfigURL")
	if err == nil {
		st.AutoConfigURL = pac
	}

	override, _, err := k.GetStringValue("ProxyOverride")
	if err == nil {
		st.Override = override
	}

	return st, nil
}

// EnableSystemProxy configures Windows 11 system proxy settings.
func EnableSystemProxy(proxyServer, pacURL string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}

	if proxyServer != "" {
		if err := k.SetStringValue("ProxyServer", proxyServer); err != nil {
			return err
		}
	}

	override := "<local>;*.local;192.168.*;10.*;172.16.*"
	_ = k.SetStringValue("ProxyOverride", override)

	if pacURL != "" {
		_ = k.SetStringValue("AutoConfigURL", pacURL)
	} else {
		_ = k.DeleteValue("AutoConfigURL")
	}

	refreshInternetSettings()
	return nil
}

// DisableSystemProxy turns off system proxy settings in Windows.
func DisableSystemProxy() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
		return err
	}

	_ = k.DeleteValue("AutoConfigURL")

	refreshInternetSettings()
	return nil
}

// IsQUICBlocked checks if the outbound QUIC firewall block rule is present.
func IsQUICBlocked() bool {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=Sinkhole Block QUIC (UDP 443 Outbound)")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return err == nil && strings.Contains(string(out), "Sinkhole Block QUIC")
}

// SetQUICBlocked toggles the outbound QUIC firewall block rule.
func SetQUICBlocked(block bool) error {
	ruleName := "Sinkhole Block QUIC (UDP 443 Outbound)"
	// Remove existing rule first to prevent duplicates
	delCmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
	delCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = delCmd.Run()

	if block {
		addCmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName, "dir=out", "action=block", "protocol=UDP", "remoteport=443")
		addCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return addCmd.Run()
	}
	return nil
}

func refreshInternetSettings() {
	_, _, _ = procInternetSetOption.Call(0, uintptr(internetOptionSettingsChanged), 0, 0)
	_, _, _ = procInternetSetOption.Call(0, uintptr(internetOptionRefresh), 0, 0)
}
