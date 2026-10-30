// Package ca manages the local Root Certificate Authority (CA) used to inspect
// and filter encrypted HTTPS traffic (e.g. YouTube player API payloads and in-page ads).
// It generates a secure local CA, installs/removes it from the Windows Trusted Root
// Certification Authorities store, and mints on-the-fly leaf certificates for target domains.
package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	CAName         = "Sinkhole HTTPS Filtering Root CA"
	CAOrganization = "Sinkhole Ad-Blocker"
	ValidYearsCA   = 10
	ValidDaysLeaf  = 90
)

// CA holds the root certificate and private key.
type CA struct {
	certPath string
	keyPath  string

	mu      sync.RWMutex
	rootCert *x509.Certificate
	rootKey  crypto.Signer
	tlsCert  tls.Certificate

	leafMu    sync.RWMutex
	leafCache map[string]*tls.Certificate
}

// LoadOrGenerate loads the CA from certDir, or generates a new one if missing.
func LoadOrGenerate(certDir string) (*CA, error) {
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return nil, fmt.Errorf("create cert dir %s: %w", certDir, err)
	}

	certPath := filepath.Join(certDir, "sinkhole_ca.crt")
	keyPath := filepath.Join(certDir, "sinkhole_ca.key")

	c := &CA{
		certPath:  certPath,
		keyPath:   keyPath,
		leafCache: make(map[string]*tls.Certificate, 256),
	}

	if fileExists(certPath) && fileExists(keyPath) {
		if err := c.load(); err == nil {
			return c, nil
		}
	}

	if err := c.generate(); err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}

	return c, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func (c *CA) load() error {
	certPEM, err := os.ReadFile(c.certPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(c.keyPath)
	if err != nil {
		return err
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}

	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.rootCert = x509Cert
	c.rootKey = tlsCert.PrivateKey.(crypto.Signer)
	c.tlsCert = tlsCert
	c.mu.Unlock()
	return nil
}

func (c *CA) generate() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         CAName,
			Organization:       []string{CAOrganization},
			OrganizationalUnit: []string{"Local HTTPS Inspection Engine"},
			Country:            []string{"US"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(ValidYearsCA * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            1,
	}

	pubKey := priv.Public()
	spkiHash := sha256.Sum256(x509.MarshalPKCS1PublicKey(&priv.PublicKey))
	tmpl.SubjectKeyId = spkiHash[:]
	tmpl.AuthorityKeyId = spkiHash[:]

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pubKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.OpenFile(c.certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(c.keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}

	return c.load()
}

// CertPath returns the absolute path to the root CA certificate PEM file.
func (c *CA) CertPath() string { return c.certPath }

// RootCertificate returns the active x509 root certificate.
func (c *CA) RootCertificate() *x509.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rootCert
}

// MintCertificate mints an on-the-fly leaf certificate for the given hostname.
func (c *CA) MintCertificate(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Check in-memory cache
	c.leafMu.RLock()
	if cert, ok := c.leafCache[host]; ok {
		c.leafMu.RUnlock()
		return cert, nil
	}
	c.leafMu.RUnlock()

	c.mu.RLock()
	rootCert := c.rootCert
	rootKey := c.rootKey
	c.mu.RUnlock()

	if rootCert == nil || rootKey == nil {
		return nil, errors.New("root CA is not initialized")
	}

	leafPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{CAOrganization},
		},
		NotBefore:             now.Add(-2 * time.Hour),
		NotAfter:              now.Add(ValidDaysLeaf * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
		// Also include wildcard if host is not already a wildcard
		if !strings.HasPrefix(host, "*.") {
			tmpl.DNSNames = append(tmpl.DNSNames, "*."+host)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert, leafPriv.Public(), rootKey)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der, rootCert.Raw},
		PrivateKey:  leafPriv,
	}

	c.leafMu.Lock()
	if len(c.leafCache) > 2000 {
		// Prune cache if overly large
		for k := range c.leafCache {
			delete(c.leafCache, k)
			if len(c.leafCache) < 1000 {
				break
			}
		}
	}
	c.leafCache[host] = tlsCert
	c.leafMu.Unlock()

	return tlsCert, nil
}

// ---------------------------------------------------------------- Windows Trust Integration

// InstallWindowsRoot registers the Root CA into the Windows Trusted Root Certification Authorities store.
func (c *CA) InstallWindowsRoot() error {
	certPath, err := filepath.Abs(c.certPath)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	// 1. Install to LocalMachine root store (for system services & all users)
	cmdMachine := exec.CommandContext(ctx, "certutil.exe", "-addstore", "-f", "Root", certPath)
	cmdMachine.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmdMachine.Run()

	// 2. Also try user store
	cmdUser := exec.CommandContext(ctx, "certutil.exe", "-addstore", "-user", "-f", "Root", certPath)
	cmdUser.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmdUser.Run()

	// 3. Configure Firefox to trust Windows Enterprise Roots
	_ = EnableFirefoxEnterpriseRoots()

	if !c.IsTrusted() {
		return errors.New("administrator elevation required: run .\\scripts\\Enable-YouTubeShield.ps1 as Administrator")
	}
	return nil
}

// UninstallWindowsRoot removes the Root CA from the Windows certificate stores.
func (c *CA) UninstallWindowsRoot() error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	cmdUser := exec.CommandContext(ctx, "certutil.exe", "-delstore", "-user", "Root", CAName)
	cmdUser.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmdUser.Run()

	cmdMachine := exec.CommandContext(ctx, "certutil.exe", "-delstore", "Root", CAName)
	cmdMachine.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmdMachine.Run()

	return nil
}

// IsTrusted checks whether the CA is installed and trusted in the Windows store.
func (c *CA) IsTrusted() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Check local machine store first
	cmdM := exec.CommandContext(ctx, "certutil.exe", "-verifystore", "Root", CAName)
	cmdM.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmdM.CombinedOutput(); err == nil && strings.Contains(string(out), CAName) {
		return true
	}

	// Check user store
	cmd := exec.CommandContext(ctx, "certutil.exe", "-verifystore", "-user", "Root", CAName)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmd.CombinedOutput(); err == nil && strings.Contains(string(out), CAName) {
		return true
	}

	return false
}

// EnableFirefoxEnterpriseRoots configures Windows Registry so Firefox automatically
// trusts the Windows Root Certificate Authorities store.
func EnableFirefoxEnterpriseRoots() error {
	script := `
$p = "HKLM:\Software\Policies\Mozilla\Firefox\Certificates"
if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
Set-ItemProperty -Path $p -Name "ImportEnterpriseRoots" -Value 1 -Type DWord -Force
`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}
