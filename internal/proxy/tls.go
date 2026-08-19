package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

type CertManager struct {
	mu       sync.RWMutex
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	certs    map[string]*tls.Certificate
}

func NewCertManager() (*CertManager, error) {
	cm := &CertManager{
		certs: make(map[string]*tls.Certificate),
	}

	if err := cm.generateCA(); err != nil {
		return nil, fmt.Errorf("generating CA: %w", err)
	}

	return cm, nil
}

func (cm *CertManager) generateCA() error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generating serial number: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GhostGuard"},
			CommonName:   "GhostGuard CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("creating CA cert: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("parsing CA cert: %w", err)
	}

	cm.caCert = caCert
	cm.caKey = caKey
	return nil
}

func (cm *CertManager) ExportCA(path string) error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cm.caCert.Raw,
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating CA file: %w", err)
	}
	defer f.Close()

	return pem.Encode(f, pemBlock)
}

func (cm *CertManager) GetCert(host string) (*tls.Certificate, error) {
	cm.mu.RLock()
	cert, ok := cm.certs[host]
	cm.mu.RUnlock()
	if ok {
		return cert, nil
	}

	return cm.generateCert(host)
}

func (cm *CertManager) generateCert(host string) (*tls.Certificate, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cert, ok := cm.certs[host]; ok {
		return cert, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GhostGuard"},
			CommonName:   host,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, cm.caCert, &key.PublicKey, cm.caKey)
	if err != nil {
		return nil, fmt.Errorf("creating cert: %w", err)
	}

	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: func() []byte {
			b, _ := x509.MarshalECPrivateKey(key)
			return b
		}()}),
	)
	if err != nil {
		return nil, fmt.Errorf("creating keypair: %w", err)
	}

	cm.certs[host] = &cert
	return &cert, nil
}

func (p *Proxy) dialTLS(addr string) (*tls.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	cert, err := p.certMgr.GetCert(host)
	if err != nil {
		return nil, fmt.Errorf("getting cert for %s: %w", host, err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("dialing %s: %w", addr, err)
	}

	return conn, nil
}
