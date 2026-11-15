package coordination

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
)

// These fields are populated only by the deployment build.
var embeddedRole, embeddedCert, embeddedKey, embeddedCA string

// TLSConfig constructs a mutually authenticated TLS configuration.
func TLSConfig(certFile, keyFile, caFile string, server bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read TLS CA: %w", err)
	}
	return tlsConfig(cert, ca, server)
}

func tlsConfig(cert tls.Certificate, ca []byte, server bool) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("TLS CA contains no certificates")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if server {
		config.ClientCAs = pool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		config.RootCAs = pool
	}
	return config, nil
}

// EmbeddedTLSConfig returns the deployment identity for the requested role.
func EmbeddedTLSConfig(server bool) (*tls.Config, error) {
	role := "client"
	if server {
		role = "server"
	}
	if embeddedRole == "" {
		return nil, fmt.Errorf("no embedded TLS credentials; --tls-cert, --tls-key and --tls-ca are required")
	}
	if embeddedRole != role {
		return nil, fmt.Errorf("this deployment binary has a %s identity, not a %s identity", embeddedRole, role)
	}
	certPEM, err := base64.StdEncoding.DecodeString(embeddedCert)
	if err != nil {
		return nil, fmt.Errorf("decode embedded TLS certificate: %w", err)
	}
	keyPEM, err := base64.StdEncoding.DecodeString(embeddedKey)
	if err != nil {
		return nil, fmt.Errorf("decode embedded TLS key: %w", err)
	}
	ca, err := base64.StdEncoding.DecodeString(embeddedCA)
	if err != nil {
		return nil, fmt.Errorf("decode embedded TLS CA: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load embedded TLS certificate: %w", err)
	}
	return tlsConfig(cert, ca, server)
}
