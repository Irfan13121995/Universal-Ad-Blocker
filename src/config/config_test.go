package config

import (
	"testing"
)

func TestParseUpstream(t *testing.T) {
	tests := []struct {
		input   string
		proto   string
		host    string
		port    string
		wantErr bool
	}{
		{"1.1.1.1", "udp", "1.1.1.1", "53", false},
		{"udp://9.9.9.9:53", "udp", "9.9.9.9", "53", false},
		{"tcp://8.8.8.8:5353", "tcp", "8.8.8.8", "5353", false},
		{"tls://dns.quad9.net", "tls", "dns.quad9.net", "853", false},
		{"https://cloudflare-dns.com/dns-query", "https", "cloudflare-dns.com", "443", false},
		{"127.0.0.1:53", "", "", "", true}, // loopback:53 rejected to avoid loop
		{"invalid://test", "", "", "", true},
	}

	for _, tt := range tests {
		u, err := ParseUpstream(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseUpstream(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr {
			if u.Proto != tt.proto {
				t.Errorf("ParseUpstream(%q) Proto = %s, want %s", tt.input, u.Proto, tt.proto)
			}
			if u.Host != tt.host {
				t.Errorf("ParseUpstream(%q) Host = %s, want %s", tt.input, u.Host, tt.host)
			}
			if u.Port != tt.port {
				t.Errorf("ParseUpstream(%q) Port = %s, want %s", tt.input, u.Port, tt.port)
			}
		}
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default config should be valid, got: %v", err)
	}

	cfg.DNSListen = []string{"not-an-ip-port"}
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected error for invalid DNSListen")
	}
}
