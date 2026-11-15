package coordination

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

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
