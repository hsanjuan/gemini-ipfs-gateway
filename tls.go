package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

const certValidityPeriod = 100 * 365 * 24 * time.Hour // ~100 years

func makeCertificate(key *ecdsa.PrivateKey, addrs []string) (tls.Certificate, error) {
	var ips []net.IP
	for _, addr := range addrs {
		ip, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("resolving address from %s: %w", addr, err)
		}
		ips = append(ips, ip.IP)
	}

	sn, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		// should always generate the same cert for the same private key
		SerialNumber: sn,
		Subject: pkix.Name{
			Organization: []string{"IPFS"},
			CommonName:   "127.0.0.1",
		},
		BasicConstraintsValid: true,
		NotBefore:             time.Time{},
		NotAfter:              time.Now().Add(certValidityPeriod),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           ips,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		logger.Error(err)
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}
