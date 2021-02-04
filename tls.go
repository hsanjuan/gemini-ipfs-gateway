package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

const certValidityPeriod = 100 * 365 * 24 * time.Hour // ~100 years

// Thanks to https://github.com/libp2p/go-libp2p-tls/blob/master/crypto.go
// This uses the libp2p host private key to create a tls certificate.
func generateTLSconfig(key *ecdsa.PrivateKey, ip net.IP) (*tls.Config, error) {
	tmpl := &x509.Certificate{
		// should always generate the same cert for the same private key
		SerialNumber: big.NewInt(5001),
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
		//IPAddresses:  []net.IP{ip},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return &tls.Config{
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: false,
		//InsecureSkipVerify:       true, // This is not insecure here. We will verify the cert chain ourselves.
		//ClientAuth:               tls.NoClientCert,
		Certificates: []tls.Certificate{*cert},

		//
		// VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
		// 	panic("tls config not specialized for peer")
		// },
		// Probably not needed
		NextProtos:             []string{"gemini"},
		SessionTicketsDisabled: true,
	}, nil
}
