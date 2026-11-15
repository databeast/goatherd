package coordination_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/databeast/goatherd/collector"
	"github.com/databeast/goatherd/internal/coordination"
	"github.com/databeast/goatherd/internal/discovery"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func testCertificates(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatal(err)
	}
	makeConfig := func(isServer bool) *tls.Config {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		usage := x509.ExtKeyUsageClientAuth
		if isServer {
			usage = x509.ExtKeyUsageServerAuth
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"localhost"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		name := "client"
		if isServer {
			name = "server"
		}
		certFile, keyFile := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem")
		if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
			t.Fatal(err)
		}
		config, err := coordination.TLSConfig(certFile, keyFile, caPath, isServer)
		if err != nil {
			t.Fatal(err)
		}
		if !isServer {
			config.ServerName = "localhost"
		}
		return config
	}
	return makeConfig(true), makeConfig(false)
}

func TestTLSConfigRejectsInvalidFiles(t *testing.T) {
	server, _ := testCertificates(t)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	key, err := x509.MarshalPKCS8PrivateKey(server.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificates[0].Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	badCA := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ cert, key, ca string }{
		{"missing", keyPath, badCA},
		{certPath, keyPath, filepath.Join(dir, "missing")},
		{certPath, keyPath, badCA},
	} {
		if _, err := coordination.TLSConfig(tt.cert, tt.key, tt.ca, true); err == nil {
			t.Fatalf("invalid TLS files accepted: %+v", tt)
		}
	}
}

func TestMutualTLSStreamingAndReports(t *testing.T) {
	serverTLS, clientTLS := testCertificates(t)
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	coordination.RegisterCoordinatorServer(server, coordination.NewServer())
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	dial := func(config *tls.Config) *grpc.ClientConn {
		conn, err := grpc.NewClient("passthrough:///localhost",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
			grpc.WithTransportCredentials(credentials.NewTLS(config)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := coordination.NewCoordinatorClient(dial(clientTLS))
	for _, name := range []string{"point-a", "point-b"} {
		stream, err := client.Collect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		sink, err := collector.NewRemoteSink(stream, name, 6, nil)
		if err != nil {
			t.Fatal(err)
		}
		gateway := net.HardwareAddr{2, 0, 0, 0, 0, 1}
		source := net.IPv4(10, 0, 0, 1)
		if name == "point-b" {
			source = net.IPv4(172, 16, 0, 1)
		}
		sink.ObserveIPv4(gateway, source, net.IPv4(203, 0, 113, 1), 61)
		sink.ObserveARP(gateway, net.IPv4(192, 0, 2, 1))
		result, err := sink.Close()
		if err != nil || result.Observations != 2 {
			t.Fatalf("stream result: %v, %v", result, err)
		}
	}
	reports, err := client.Reports(ctx, &coordination.ReportsRequest{})
	if err != nil || len(reports.Reports) != 2 {
		t.Fatalf("reports: %v, %v", reports, err)
	}
	for i, expected := range []string{"10.0.0.1/32", "172.16.0.1/32"} {
		var report discovery.Report
		if err := json.Unmarshal(reports.Reports[i].ReportJson, &report); err != nil {
			t.Fatal(err)
		}
		if report.Overall.Prefix != expected || report.ForwardedPackets != 1 {
			t.Fatalf("report: %+v", report)
		}
	}
	stream, err := client.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&coordination.Observation{Data: &coordination.Observation_Registration{
		Registration: &coordination.Registration{CapturePoint: "point-a"},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.CloseAndRecv(); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected duplicate rejection, got %v", err)
	}
	invalid, err := client.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := invalid.Send(&coordination.Observation{Data: &coordination.Observation_Registration{
		Registration: &coordination.Registration{CapturePoint: "invalid"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := invalid.Send(&coordination.Observation{Data: &coordination.Observation_Arp{
		Arp: &coordination.ARP{Mac: []byte{1, 2, 3}, Ip: []byte{1, 2, 3, 4}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := invalid.CloseAndRecv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected malformed observation rejection, got %v", err)
	}
	reports, err = client.Reports(ctx, &coordination.ReportsRequest{})
	if err != nil || len(reports.Reports) != 3 || reports.Reports[0].Error == "" {
		t.Fatalf("expected explicit incomplete capture error: %v, %v", reports, err)
	}
	unauthenticated := clientTLS.Clone()
	unauthenticated.Certificates = nil
	if _, err := coordination.NewCoordinatorClient(dial(unauthenticated)).Reports(ctx, &coordination.ReportsRequest{}); err == nil {
		t.Fatal("unauthenticated client accepted")
	}
}
