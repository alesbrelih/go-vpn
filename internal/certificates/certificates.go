package certificates

import (
	"alesbrelih/go-vpn/resources/ca"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

type Config struct {
	Key  string `yaml:"key"`
	Cert string `yaml:"cert"`
}

func Generate(commonName string, ipAddress net.IP) ([]byte, []byte, error) {
	caCertPEMDecoded, _ := pem.Decode(ca.CertPEM)
	if caCertPEMDecoded == nil {
		return nil, nil, errors.New("could not PEM decode the cert")
	}

	caCert, err := x509.ParseCertificate(caCertPEMDecoded.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse CA cert; err: %w", err)
	}

	caKeyPEMDecoded, _ := pem.Decode(ca.KeyPEM)
	if caKeyPEMDecoded == nil {
		return nil, nil, errors.New("could not PEM decode the key")
	}

	caKey, err := x509.ParsePKCS8PrivateKey(caKeyPEMDecoded.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse CA key; err: %w", err)
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate cert key; err: %w", err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	if ipAddress != nil {
		certTemplate.IPAddresses = []net.IP{ipAddress}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, &certKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate cert; err: %w", err)
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certKey),
	})

	return certPEM.Bytes(), certPrivKeyPEM.Bytes(), nil
}
