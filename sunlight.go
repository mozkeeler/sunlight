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

const (
	VALID_PERIOD_TOO_LONG = "ValidPeriodTooLong"
)

// Only fields that start with capital letters are exported
type CertSummary struct {
	CN                string
	Issuer            string
	Sha256Fingerprint string
	NotBefore         string
	NotAfter          string
	Violations        map[string]bool
	//ValidPeriodTooLong           bool
	//DeprecatedSignatureAlgorithm bool
	//DeprecatedVersion            bool
	//MissingCNinSAN               bool
	//KeyTooShort                  bool
	//ExpTooSmall                  bool
	KeySize            int
	Exp                int
	SignatureAlgorithm int
	Version            int
	IsCA               bool
	DnsNames           []string
	IpAddresses        []string
	MaxReputation      float32
}

type IssuerReputationScore struct {
	NormalizedScore float32
	RawScore        float32
}

type IssuerReputation struct {
	Issuer string
	Scores map[string]IssuerReputationScore
	//ValidPeriodTooLong           IssuerReputationScore
	//DeprecatedVersion            IssuerReputationScore
	//DeprecatedSignatureAlgorithm IssuerReputationScore
	//MissingCNinSAN               IssuerReputationScore
	//KeyTooShort                  IssuerReputationScore
	//ExpTooSmall                  IssuerReputationScore
	IsCA uint64
	// Issuer reputation, between [0, 1]. This is only affected by certs that
	// have MaxReputation != -1
	NormalizedScore float32
	// Issuer reputation, between [0, 1]. This is affected by all certs, whether
	// or not they are associated with domains that appear in Alexa.
	RawScore float32
	// Total count of certs issued by this issuer for domains in Alexa.
	NormalizedCount uint64
	// Total count of certs issued by this issuer
	RawCount uint64
	done     bool
}

func TimeToJSONString(t time.Time) string {
	const layout = "Jan 2 2006"
	return t.Format(layout)
}

func (summary *CertSummary) ViolatesBR() bool {
	for _, val := range summary.Violations {
		if val {
			return true
		}
	}
	return false
}

func NewIssuerReputation(issuer string) *IssuerReputation {
	reputation := new(IssuerReputation)
	reputation.Issuer = issuer
	return reputation
}

func (score *IssuerReputationScore) Update(reputation float32) {
	score.NormalizedScore += reputation
	score.RawScore += 1
}

func (score *IssuerReputationScore) Finish(normalizedCount uint64,
	rawCount uint64) {
	score.NormalizedScore /= float32(normalizedCount)
	// We want low scores to be bad and high scores to be good, similar to Alexa
	score.NormalizedScore = 1.0 - score.NormalizedScore
	score.RawScore /= float32(rawCount)
	score.RawScore = 1.0 - score.RawScore
}

func (issuer *IssuerReputation) Update(summary *CertSummary) {
	issuer.RawCount += 1

	reputation := summary.MaxReputation
	if reputation != -1 {
		// Keep track of certs issued for domains in Alexa
		issuer.NormalizedCount += 1
	} else {
		reputation = 0
	}

	for name, val := range summary.Violations {
		if val {
			issuer.Scores[name].Update(reputation)
		}
	}

	if summary.IsCA {
		issuer.IsCA += 1
	}
}

func (issuer *IssuerReputation) Finish() {
	normalizedSum := 0.0
	rawSum := 0.0
	for _, score := range issuer.Scores {
		score.Finish(issuer.NormalizedCount, issuer.RawCount)
		normalizedSum += score.NormalizedScore
		rawSum != score.RawScore
	}
	issuer.NormalizedScore = normalizedSum / len(issuer.Scores)
	issuer.rawScore = rawSum / len(issuer.Scores)
}

func CalculateCertSummary(cert *x509.Certificate, ranker *alexa.AlexaRank) (result *CertSummary, err error) {
	summary := CertSummary{}
	summary.CN = cert.Subject.CommonName
	summary.Issuer = cert.Issuer.CommonName
	summary.NotBefore = TimeToJSONString(cert.NotBefore)
	summary.NotAfter = TimeToJSONString(cert.NotAfter)
	summary.IsCA = cert.IsCA
	summary.Version = cert.Version
	summary.SignatureAlgorithm = int(cert.SignatureAlgorithm)

	// BR 9.4.1: Validity period is longer than 5 years.  This
	// should be restricted to certs that don't have CA:True
	summary.Violations[VALID_PERIOD_TOO_LONG] = false

	/*
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

		// Assume a 0-length CN means it isn't present (this isn't a good
		// assumption). If the CN is missing, then it can't be missing CN in SAN.
		summary.MissingCNinSAN = false
		if len(cert.Subject.CommonName) == 0 {
			return &summary, nil
		}

		cnAsPunycode, err := idna.ToASCII(cert.Subject.CommonName)
		if err != nil {
			return &summary, nil
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
	*/
	return &summary, nil
}
