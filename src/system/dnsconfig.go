//go:build windows

// Package system adjusts Windows network adapter DNS settings so the local
// machine can use the sinkhole (127.0.0.1 / ::1). It shells out to the
// built-in NetTCPIP / DnsClient PowerShell modules and requires administrator
// rights (the Windows service runs as LocalSystem, which has them).
package system

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Adapter describes a network adapter and its DNS configuration.
type Adapter struct {
	Index         int      `json:"index"`
	Alias         string   `json:"alias"`
	Description   string   `json:"description"`
	Status        string   `json:"status"`
	IPv4          []string `json:"ipv4"`
	IPv4DNS       []string `json:"ipv4_dns"`
	IPv6DNS       []string `json:"ipv6_dns"`
	StaticV4      string   `json:"static_v4"` // registry NameServer (empty = DHCP)
	StaticV6      string   `json:"static_v6"`
	UsesSinkhole  bool     `json:"uses_sinkhole"`
	HasBackup     bool     `json:"has_backup"`
}

// Backup is the DNS configuration captured before switching to the sinkhole.
type Backup struct {
	StaticV4 []string `json:"static_v4"`
	StaticV6 []string `json:"static_v6"`
}

func run(ctx context.Context, script string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "Access is denied") || strings.Contains(msg, "PermissionDenied") || strings.Contains(msg, "0x80041003") {
			return out, errors.New("access denied: changing adapter DNS requires administrator rights (run the Windows service or an elevated console)")
		}
		if len(msg) > 600 {
			msg = msg[:600]
		}
		return out, fmt.Errorf("%v: %s", err, msg)
	}
	return out, nil
}

const listScript = `
$list = @(Get-NetAdapter | Where-Object { $_.Status -ne 'Not Present' -and $_.HardwareInterface -or $_.Status -eq 'Up' } | ForEach-Object {
  $a = $_
  $v4 = (Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
  $v6 = (Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses
  $ip = (Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
  $g = $a.InterfaceGuid
  $s4 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$g" -Name NameServer -ErrorAction SilentlyContinue).NameServer
  $s6 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$g" -Name NameServer -ErrorAction SilentlyContinue).NameServer
  [pscustomobject]@{
    index = [int]$a.ifIndex; alias = $a.Name; description = $a.InterfaceDescription; status = [string]$a.Status
    ipv4 = @($ip | Where-Object { $_ }); ipv4_dns = @($v4 | Where-Object { $_ }); ipv6_dns = @($v6 | Where-Object { $_ })
    static_v4 = [string]$s4; static_v6 = [string]$s6
  }
})
ConvertTo-Json -InputObject $list -Depth 4 -Compress
`

// ListAdapters returns physical / active adapters with their DNS servers.
func ListAdapters(ctx context.Context) ([]Adapter, error) {
	out, err := run(ctx, listScript)
	if err != nil {
		return nil, err
	}
	var list []Adapter
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &list); err != nil {
		return nil, fmt.Errorf("parse adapter list: %w", err)
	}
	for i := range list {
		for _, d := range append(append([]string{}, list[i].IPv4DNS...), list[i].IPv6DNS...) {
			if ip := net.ParseIP(d); ip != nil && ip.IsLoopback() {
				list[i].UsesSinkhole = true
			}
		}
	}
	return list, nil
}

func splitServers(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if ip := net.ParseIP(f); ip != nil && !ip.IsLoopback() {
			out = append(out, ip.String())
		}
	}
	return out
}

// CaptureBackup returns the current static DNS servers of an adapter.
func CaptureBackup(a Adapter) Backup {
	return Backup{StaticV4: splitServers(a.StaticV4), StaticV6: splitServers(a.StaticV6)}
}

// PointToSinkhole sets the adapter's DNS servers to 127.0.0.1 and ::1.
func PointToSinkhole(ctx context.Context, index int) error {
	_, err := run(ctx, fmt.Sprintf(
		`Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses ('127.0.0.1','::1'); Clear-DnsClientCache`, index))
	return err
}

// Restore reverts an adapter to its backed-up static servers, or to DHCP.
func Restore(ctx context.Context, index int, b *Backup) error {
	var servers []string
	if b != nil {
		for _, s := range append(append([]string{}, b.StaticV4...), b.StaticV6...) {
			if net.ParseIP(s) != nil { // validated: safe to interpolate
				servers = append(servers, "'"+s+"'")
			}
		}
	}
	script := fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceIndex %d -ResetServerAddresses`, index)
	if len(servers) > 0 {
		script = fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses (%s)`, index, strings.Join(servers, ","))
	}
	_, err := run(ctx, script+"; Clear-DnsClientCache")
	return err
}

// FlushClientCache clears the Windows DNS client cache.
func FlushClientCache(ctx context.Context) error {
	_, err := run(ctx, "Clear-DnsClientCache")
	return err
}
