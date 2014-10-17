package sunlight

import (
	"code.google.com/p/go.net/idna"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	_ "github.com/mattn/go-sqlite3"
	"github.com/monicachew/alexa"
	"net"
	"strings"
	"time"
)

// Only fields that start with capital letters are exported
type CertSummary struct {
	CN                           string
	Issuer                       string
	Sha256Fingerprint            string
	NotBefore                    string
	NotAfter                     string
	ValidPeriodTooLong           bool
	DeprecatedSignatureAlgorithm bool
	DeprecatedVersion            bool
	MissingCNinSAN               bool
	KeyTooShort                  bool
	KeySize                      int
	ExpTooSmall                  bool
	Exp                          int
	SignatureAlgorithm           int
	Version                      int
	IsCA                         bool
	DnsNames                     []string
	IpAddresses                  []string
	MaxReputation                float32
}

type IssuerReputation struct {
	Issuer                            string
	ValidPeriodTooLong                uint64
	ValidPeriodTooLongScore           float32
	DeprecatedVersion                 uint64
	DeprecatedVersionScore            float32
	DeprecatedSignatureAlgorithm      uint64
	DeprecatedSignatureAlgorithmScore float32
	MissingCNinSAN                    uint64
	MissingCNinSANScore               float32
	KeyTooShort                       uint64
	KeyTooShortScore                  float32
	ExpTooSmall                       uint64
	ExpTooSmallScore                  float32
	IsCA                              uint64
	Reputation                        float32
}

func TimeToJSONString(t time.Time) string {
	const layout = "Jan 2 2006"
	return t.Format(layout)
}

func (summary *CertSummary) ViolatesBR() (retval bool) {
	return summary.ValidPeriodTooLong || summary.DeprecatedSignatureAlgorithm ||
		summary.DeprecatedVersion || summary.MissingCNinSAN ||
		summary.KeyTooShort || summary.ExpTooSmall
}

func CalculateCertSummary(cert *x509.Certificate, ranker *alexa.AlexaRank) (result *CertSummary, err error) {
	summary := CertSummary{}
	// Assume a 0-length CN means it isn't present (this isn't a good assumption)
	if len(cert.Subject.CommonName) == 0 {
		return
	}

	// Filter out certs issued before 2013 or that have already
	// expired.
	now := time.Now()
	if cert.NotBefore.Before(time.Date(2013, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		cert.NotAfter.Before(now) {
		return
	}

	cnAsPunycode, err := idna.ToASCII(cert.Subject.CommonName)
	if err != nil {
		return
	}
	// BR 9.2.2: Found Common Name in Subject Alt Names, either as an IP or a
	// DNS name.
	summary.MissingCNinSAN = true
	cnAsIP := net.ParseIP(cert.Subject.CommonName)
	if cnAsIP != nil {
		for _, ip := range cert.IPAddresses {
			if cnAsIP.Equal(ip) {
				summary.MissingCNinSAN = false
			}
		}
	} else {
		for _, san := range cert.DNSNames {
			if err == nil && strings.EqualFold(san, cnAsPunycode) {
				summary.MissingCNinSAN = false
			}
		}
	}

	// BR 9.4.1: Validity period is longer than 5 years.  This
	// should be restricted to certs that don't have CA:True
	summary.ValidPeriodTooLong = false
	if cert.NotAfter.After(cert.NotBefore.AddDate(5, 0, 7)) &&
		(!cert.BasicConstraintsValid || (cert.BasicConstraintsValid && !cert.IsCA)) {
		summary.ValidPeriodTooLong = true
	}

	// SignatureAlgorithm is SHA1
	summary.DeprecatedSignatureAlgorithm = false
	if cert.SignatureAlgorithm == x509.SHA1WithRSA ||
		cert.SignatureAlgorithm == x509.DSAWithSHA1 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {
		summary.DeprecatedSignatureAlgorithm = true
	}

	// Uses v1 certificates
	summary.DeprecatedVersion = cert.Version != 3

	// Public key length <= 1024 bits
	summary.KeyTooShort = false
	summary.ExpTooSmall = false
	summary.KeySize = -1
	summary.Exp = -1
	parsedKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if ok {
		summary.KeySize = parsedKey.N.BitLen()
		summary.Exp = parsedKey.E
		if summary.KeySize <= 1024 {
			summary.KeyTooShort = true
		}
		if summary.Exp <= 3 {
			summary.ExpTooSmall = true
		}
	}

	summary.MaxReputation, _ = ranker.GetReputation(cert.Subject.CommonName)
	for _, host := range cert.DNSNames {
		reputation, _ := ranker.GetReputation(host)
		if reputation > summary.MaxReputation {
			summary.MaxReputation = reputation
		}
	}
	sha256hasher := sha256.New()
	sha256hasher.Write(cert.Raw)
	summary.Sha256Fingerprint = base64.StdEncoding.EncodeToString(sha256hasher.Sum(nil))

	// DNS names and IP addresses
	summary.DnsNames = cert.DNSNames
	for _, address := range cert.IPAddresses {
		summary.IpAddresses = append(summary.IpAddresses, address.String())
	}
	return &summary, nil
}
