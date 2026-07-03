package core

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

type SSLCheckerModule struct{}

func (m *SSLCheckerModule) Name() string {
	return "SSL_Checker"
}

type SSLReport struct {
	Issuer           string    `json:"issuer"`
	Subject          string    `json:"subject"`
	ValidFrom        time.Time `json:"valid_from"`
	ValidUntil       time.Time `json:"valid_until"`
	DaysRemaining    int       `json:"days_remaining"`
	CipherSuite      string    `json:"cipher_suite"`
	Version          string    `json:"tls_version"`
	AlternativeNames []string  `json:"sans"`
}

func (m *SSLCheckerModule) Execute(target string) (interface{}, error) {
	config := &tls.Config{InsecureSkipVerify: true}

	// FIX: Use net.Dialer to enforce the timeout
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	// FIX: Use tls.DialWithDialer
	conn, err := tls.DialWithDialer(dialer, "tcp", target+":443", config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// conn is already a *tls.Conn, so we can directly call ConnectionState()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	cert := state.PeerCertificates[0]
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

	var tlsVer string
	switch state.Version {
	case tls.VersionTLS13:
		tlsVer = "TLS 1.3"
	case tls.VersionTLS12:
		tlsVer = "TLS 1.2"
	default:
		tlsVer = "Legacy TLS"
	}

	report := SSLReport{
		Issuer:           cert.Issuer.CommonName,
		Subject:          cert.Subject.CommonName,
		ValidFrom:        cert.NotBefore,
		ValidUntil:       cert.NotAfter,
		DaysRemaining:    daysRemaining,
		CipherSuite:      tls.CipherSuiteName(state.CipherSuite),
		Version:          tlsVer,
		AlternativeNames: cert.DNSNames,
	}

	return report, nil
}
