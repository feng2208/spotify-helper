package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

const (
	caKeyFile  = "sp-helper-ca.key"
	caCertFile = "sp-helper-ca.crt"
)

// Manager manages CA certificate and generates server certificates for MITM
type Manager struct {
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	certCache  map[string]*tls.Certificate
	cacheMutex sync.RWMutex
}

// NewManager creates a new CA manager, loading or generating CA certificate
func NewManager() (*Manager, error) {
	m := &Manager{
		certCache: make(map[string]*tls.Certificate),
	}

	// Try to load existing CA
	if err := m.loadCA(); err != nil {
		fmt.Println("Generating new CA certificate...")
		if err := m.generateCA(); err != nil {
			return nil, fmt.Errorf("failed to generate CA: %w", err)
		}
		if err := m.saveCA(); err != nil {
			return nil, fmt.Errorf("failed to save CA: %w", err)
		}
	} else {
		fmt.Println("Loaded existing CA certificate")
	}

	return m, nil
}

// loadCA loads CA certificate and key from files
func (m *Manager) loadCA() error {
	// Load CA certificate
	certPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to parse CA certificate PEM")
	}

	m.caCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	// Load CA private key
	keyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return err
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("failed to parse CA key PEM")
	}

	m.caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	return nil
}

// generateCA generates a new self-signed CA certificate valid for 10 years
func (m *Manager) generateCA() error {
	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	m.caKey = key

	// Calculate Subject Key Identifier (SKI)
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	var subjectKeyId []byte
	// SubjectKeyIdentifier is usually the SHA1 hash of the public key
	// but the raw public key bytes (excluding the AlgorithmIdentifier/BIT STRING wrapper)
	// Go's MarshalPKIXPublicKey includes the wrapper.
	// For simplicity, hashing the whole thing is often accepted, or we can use the pkix struct.
	// Actually, standard practice for SKI:
	// The SKI extension is composed of the 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey (excluding the tag, length, and number of unused bits).
	// However, simple SHA1 of the marshaled key is robust enough for most internal CAs.
	// Let's use the standard Go way if we can parse it, or just hash the bytes.
	// A simpler robust way:
	hash := sha1.Sum(pubBytes)
	subjectKeyId = hash[:]

	// Create CA certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SP Helper CA"},
			CommonName:   "SP Helper Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          subjectKeyId,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	m.caCert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}

	return nil
}

// saveCA saves CA certificate and key to files
func (m *Manager) saveCA() error {
	// Save certificate
	certFile, err := os.Create(caCertFile)
	if err != nil {
		return err
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw}); err != nil {
		return err
	}

	// Save private key
	keyFile, err := os.Create(caKeyFile)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(m.caKey)}); err != nil {
		return err
	}

	return nil
}

// GetCertificate returns a TLS certificate for the given hostname, generating if needed
func (m *Manager) GetCertificate(hostname string) (*tls.Certificate, error) {
	// Check cache first
	m.cacheMutex.RLock()
	if cert, ok := m.certCache[hostname]; ok {
		m.cacheMutex.RUnlock()
		return cert, nil
	}
	m.cacheMutex.RUnlock()

	// Generate new certificate
	cert, err := m.generateCert(hostname)
	if err != nil {
		return nil, err
	}

	// Cache it
	m.cacheMutex.Lock()
	m.certCache[hostname] = cert
	m.cacheMutex.Unlock()

	return cert, nil
}

// generateCert generates a server certificate for the given hostname
func (m *Manager) generateCert(hostname string) (*tls.Certificate, error) {
	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	// Calculate Subject Key Identifier (SKI) for the leaf
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	hash := sha1.Sum(pubBytes)
	subjectKeyId := hash[:]

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SP Helper"},
			CommonName:   hostname,
		},
		NotBefore:             time.Now().Add(-10 * time.Minute), // Backdate slightly to avoid sync issues
		NotAfter:              time.Now().AddDate(1, 0, 0),       // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{hostname},
		SubjectKeyId:          subjectKeyId,
	}

	// Sign with CA
	// CreateCertificate will automatically prompt AuthorityKeyId from the parent (m.caCert)
	// because m.caCert now (after regeneration) has a SubjectKeyId.
	certDER, err := x509.CreateCertificate(rand.Reader, &template, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER, m.caCert.Raw},
		PrivateKey:  key,
	}

	return cert, nil
}

// GetCACert returns the CA certificate in PEM format
func (m *Manager) GetCACert() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw})
}
