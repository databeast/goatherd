package coordination

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestEmbeddedTLSRejectsWrongRoleAndMalformedCredentials(t *testing.T) {
	oldRole, oldCert, oldKey, oldCA := embeddedRole, embeddedCert, embeddedKey, embeddedCA
	t.Cleanup(func() {
		embeddedRole, embeddedCert, embeddedKey, embeddedCA = oldRole, oldCert, oldKey, oldCA
	})
	embeddedRole, embeddedCert, embeddedKey, embeddedCA = "client", "", "", ""
	if _, err := EmbeddedTLSConfig(true); err == nil || !strings.Contains(err.Error(), "client identity") {
		t.Fatalf("wrong role: %v", err)
	}
	embeddedCert = "!"
	if _, err := EmbeddedTLSConfig(false); err == nil || !strings.Contains(err.Error(), "decode embedded TLS certificate") {
		t.Fatalf("invalid certificate encoding: %v", err)
	}
	embeddedCert = base64.StdEncoding.EncodeToString([]byte("not a certificate"))
	embeddedKey = base64.StdEncoding.EncodeToString([]byte("not a key"))
	embeddedCA = base64.StdEncoding.EncodeToString([]byte("not a CA"))
	if _, err := EmbeddedTLSConfig(false); err == nil || !strings.Contains(err.Error(), "load embedded TLS certificate") {
		t.Fatalf("invalid keypair: %v", err)
	}
}
