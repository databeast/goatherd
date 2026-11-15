// Command deploybuild creates a short-lived trust group and its static binaries.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type identity struct {
	cert []byte
	key  []byte
}

func serial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	if n.Sign() == 0 {
		return big.NewInt(1), nil
	}
	return n, nil
}

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func credentials(host string, now time.Time) ([]byte, identity, identity, error) {
	if !validHost(host) {
		return nil, identity{}, identity{}, fmt.Errorf("invalid coordinator DNS name or IP %q", host)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, identity{}, identity{}, err
	}
	caSerial, err := serial()
	if err != nil {
		return nil, identity{}, identity{}, err
	}
	ca := &x509.Certificate{
		SerialNumber: caSerial, Subject: pkix.Name{CommonName: "goatherd deployment CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, identity{}, identity{}, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, identity{}, identity{}, err
	}
	makeIdentity := func(server bool) (identity, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return identity{}, err
		}
		number, err := serial()
		if err != nil {
			return identity{}, err
		}
		template := &x509.Certificate{
			SerialNumber: number, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if server {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			if ip := net.ParseIP(host); ip != nil {
				template.IPAddresses = []net.IP{ip}
			} else {
				template.DNSNames = []string{host}
			}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		if err != nil {
			return identity{}, err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return identity{}, err
		}
		return identity{
			cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			key:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		}, nil
	}
	server, err := makeIdentity(true)
	if err != nil {
		return nil, identity{}, identity{}, err
	}
	client, err := makeIdentity(false)
	if err != nil {
		return nil, identity{}, identity{}, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), server, client, nil
}

func build(path, role string, ca []byte, id identity) error {
	const prefix = "github.com/databeast/goatherd/internal/coordination."
	encode := base64.StdEncoding.EncodeToString
	flags := fmt.Sprintf("-linkmode external -extldflags '-static' -X %sembeddedRole=%s -X %sembeddedCA=%s -X %sembeddedCert=%s -X %sembeddedKey=%s",
		prefix, role, prefix, encode(ca), prefix, encode(id.cert), prefix, encode(id.key))
	cmd := exec.Command("go", "build", "-tags", "netgo,osusergo", "-ldflags", flags, "-o", path, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build %s binary: %w", role, err)
	}
	if err := os.Chmod(path, 0700); err != nil {
		return fmt.Errorf("restrict %s binary permissions: %w", role, err)
	}
	for _, args := range [][]string{{"-h", path}, {"-l", path}, {"-d", path}} {
		output, err := exec.Command("readelf", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("inspect %s binary: %w: %s", role, err, output)
		}
		if bytes.Contains(output, []byte("INTERP")) || bytes.Contains(output, []byte("(NEEDED)")) {
			return fmt.Errorf("%s binary has dynamic dependencies", role)
		}
	}
	return nil
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("usage: deploybuild OUTPUT_DIRECTORY (COORDINATOR_HOST must be set)")
	}
	host := os.Getenv("COORDINATOR_HOST")
	ca, server, client, err := credentials(host, time.Now())
	if err != nil {
		return err
	}
	for _, target := range []struct {
		name, role string
		id         identity
	}{{"goatherd-coordinator", "server", server}, {"goatherd-sensor", "client", client}} {
		path := filepath.Join(os.Args[1], target.name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("reserve output %s: %w", path, err)
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := build(path, target.role, ca, target.id); err != nil {
			return err
		}
	}
	fmt.Printf("Deployment binaries built for coordinator %s; certificates expire in 30 days.\n", host)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
