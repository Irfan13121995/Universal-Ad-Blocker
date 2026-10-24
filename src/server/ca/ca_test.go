package ca

import (
	"os"
	"testing"
)

func TestCAGenerateAndMint(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sinkhole_ca_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	c, err := LoadOrGenerate(tempDir)
	if err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	if c.RootCertificate() == nil {
		t.Fatal("Root certificate is nil")
	}

	// Mint certificate for youtube.com
	leaf, err := c.MintCertificate("youtube.com")
	if err != nil {
		t.Fatalf("MintCertificate failed: %v", err)
	}
	if leaf == nil || len(leaf.Certificate) < 2 {
		t.Fatalf("invalid leaf certificate chain")
	}

	// Verify cached
	leafCached, err := c.MintCertificate("youtube.com")
	if err != nil || leaf != leafCached {
		t.Fatalf("expected cached certificate pointer to match")
	}

	// Mint certificate for subdomain with port
	leafSub, err := c.MintCertificate("s.youtube.com:443")
	if err != nil {
		t.Fatalf("MintCertificate for host:port failed: %v", err)
	}
	if leafSub == nil {
		t.Fatal("expected leafSub to be non-nil")
	}
}
