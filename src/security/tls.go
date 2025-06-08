// security/tls.go
package security

import (
	"crypto/tls"
	"log"

	"github.com/cloudflare/circl/kem/hybrid"
)

// LoadTLSConfig loads TLS configuration with hybrid X25519+Kyber768.
func LoadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	hybridKEM := hybrid.X25519Kyber768()
	curveIDs := []tls.CurveID{tls.X25519Kyber768Draft00, tls.X25519}

	config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   curveIDs,
		InsecureSkipVerify: false, // Enforce verification in production
		ClientSessionCache: tls.NewLRUClientSessionCache(100),
	}

	log.Println("TLS configured with X25519+Kyber768 hybrid key agreement")
	return config, nil
}
