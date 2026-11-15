package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestCredentialsGenerateSeparateVerifiedIdentities(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	for _, host := range []string{"coordinator.example", "192.0.2.5", "2001:db8::1"} {
		t.Run(host, func(t *testing.T) {
			ca, server, client, err := credentials(host, now)
			if err != nil {
				t.Fatal(err)
			}
			serverPair, err := tls.X509KeyPair(server.cert, server.key)
			if err != nil {
				t.Fatal(err)
			}
			clientPair, err := tls.X509KeyPair(client.cert, client.key)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(server.key, client.key) {
				t.Fatal("server and client share a private key")
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(ca) {
				t.Fatal("invalid CA")
			}
			verify := func(der []byte, name string, usage x509.ExtKeyUsage, want bool) {
				t.Helper()
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				_, err = cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: name, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}})
				if (err == nil) != want {
					t.Fatalf("verify name=%s usage=%v: %v", name, usage, err)
				}
			}
			verify(serverPair.Certificate[0], host, x509.ExtKeyUsageServerAuth, true)
			verify(serverPair.Certificate[0], "wrong.example", x509.ExtKeyUsageServerAuth, false)
			verify(serverPair.Certificate[0], "", x509.ExtKeyUsageClientAuth, false)
			verify(clientPair.Certificate[0], "", x509.ExtKeyUsageClientAuth, true)
			verify(clientPair.Certificate[0], "", x509.ExtKeyUsageServerAuth, false)
			block, _ := pem.Decode(ca)
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil || !cert.IsCA || cert.NotAfter.Sub(now) != 30*24*time.Hour {
				t.Fatalf("CA validity: %v, %v", cert, err)
			}
		})
	}
}

func TestCredentialsRejectInvalidHostsAndRegenerateCA(t *testing.T) {
	for _, host := range []string{"", "host:8432", "-host", "a..b", "foo\nbar", "*.example"} {
		if _, _, _, err := credentials(host, time.Now()); err == nil {
			t.Errorf("accepted invalid hostname %q", host)
		}
	}
	first, _, _, err := credentials("localhost", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, _, _, err := credentials("localhost", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("deployment CA reused")
	}
}
