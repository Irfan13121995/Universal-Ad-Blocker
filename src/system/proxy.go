//go:build windows

package system

import (
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

func refreshInternetSettings() {
	_, _, _ = procInternetSetOption.Call(0, uintptr(internetOptionSettingsChanged), 0, 0)
	_, _, _ = procInternetSetOption.Call(0, uintptr(internetOptionRefresh), 0, 0)
}
