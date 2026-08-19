package proxy

import (
	"os"
	"testing"
)

func TestCertManagerGenerateCA(t *testing.T) {
	cm, err := NewCertManager()
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	if cm.caCert == nil {
		t.Fatal("CA cert should not be nil")
	}
	if cm.caKey == nil {
		t.Fatal("CA key should not be nil")
	}
	if !cm.caCert.IsCA {
		t.Fatal("CA cert should have IsCA=true")
	}
}

func TestCertManagerGetCert(t *testing.T) {
	cm, err := NewCertManager()
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	cert1, err := cm.GetCert("api.openai.com")
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if cert1 == nil {
		t.Fatal("cert should not be nil")
	}

	cert2, err := cm.GetCert("api.openai.com")
	if err != nil {
		t.Fatalf("GetCert second call: %v", err)
	}

	if cert1 != cert2 {
		t.Error("should return cached cert for same host")
	}
}

func TestCertManagerDifferentHosts(t *testing.T) {
	cm, err := NewCertManager()
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	cert1, _ := cm.GetCert("api.openai.com")
	cert2, _ := cm.GetCert("api.anthropic.com")

	if cert1 == cert2 {
		t.Error("different hosts should get different certs")
	}
}

func TestCertManagerCaches(t *testing.T) {
	cm, err := NewCertManager()
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	cm.GetCert("example.com")

	cm.mu.RLock()
	count := len(cm.certs)
	cm.mu.RUnlock()

	if count != 1 {
		t.Errorf("expected 1 cached cert, got %d", count)
	}
}

func TestCertManagerExportCA(t *testing.T) {
	cm, err := NewCertManager()
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	tmpFile := t.TempDir() + "/test-ca.pem"
	if err := cm.ExportCA(tmpFile); err != nil {
		t.Fatalf("ExportCA: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("reading exported CA: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("exported CA should not be empty")
	}
}
