package sunlight

import (
	"code.google.com/p/go.net/idna"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/monicachew/alexa"
	"github.com/monicachew/certificatetransparency"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"
)

const (
	VALID_PERIOD_TOO_LONG          = "ValidPeriodTooLong"
	DEPRECATED_SIGNATURE_ALGORITHM = "DeprecatedSignatureAlgorithm"
	DEPRECATED_VERSION             = "DeprecatedVersion"
	MISSING_CN_IN_SAN              = "MissingCNInSan"
	KEY_TOO_SHORT                  = "KeyTooShort"
	EXP_TOO_SMALL                  = "ExpTooSmall"
)

// Only fields that start with capital letters are exported
type CertSummary struct {
	CN                 string
	Issuer             string
	Sha256Fingerprint  string
	NotBefore          string
	NotAfter           string
	KeySize            int
	Exp                int
	SignatureAlgorithm int
	Version            int
	IsCA               bool
	DnsNames           []string
	IpAddresses        []string
	Violations         map[string]bool
	MaxReputation      float32
	IssuerInMozillaDB  bool
}

type IssuerReputationScore struct {
	NormalizedScore float32
	RawScore        float32
}

type IssuerReputation struct {
	Issuer            string
	IssuerInMozillaDB bool
	Scores            map[string]*IssuerReputationScore
	IsCA              uint64
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

func containsIssuerInRootList(certChain []*x509.Certificate, rootCAMap map[string]bool) bool {
	for _, cert := range certChain {
		if rootCAMap[cert.Issuer.CommonName] {
			return true
		}
	}
	return false
}

func NewIssuerReputation(issuer string) *IssuerReputation {
	reputation := new(IssuerReputation)
	reputation.Issuer = issuer
	reputation.Scores = make(map[string]*IssuerReputationScore)
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
	issuer.IssuerInMozillaDB = summary.IssuerInMozillaDB
	reputation := summary.MaxReputation
	if reputation != -1 {
		// Keep track of certs issued for domains in Alexa
		issuer.NormalizedCount += 1
	} else {
		reputation = 0
	}

	for name, val := range summary.Violations {
		if issuer.Scores[name] == nil {
			issuer.Scores[name] = new(IssuerReputationScore)
		}
		if val {
			issuer.Scores[name].Update(reputation)
		}
	}

	if summary.IsCA {
		issuer.IsCA += 1
	}
}

func (issuer *IssuerReputation) Finish() {
	normalizedSum := float32(0.0)
	rawSum := float32(0.0)
	for _, score := range issuer.Scores {
		score.Finish(issuer.NormalizedCount, issuer.RawCount)
		normalizedSum += score.NormalizedScore
		rawSum += score.RawScore
	}
	issuer.NormalizedScore = normalizedSum / float32(len(issuer.Scores))
	issuer.RawScore = rawSum / float32(len(issuer.Scores))
}

func CalculateCertSummary(ent *certificatetransparency.EntryAndPosition, ranker *alexa.AlexaRank, rootCAMap map[string]bool) (result *CertSummary, err error) {
	cert, err := x509.ParseCertificate(ent.Entry.X509Cert)
	if err != nil {
		return nil, errors.New("Couldn't parse certificate")
	}

	// Filter out certs issued before 2013 or that have already
	// expired.
	now := time.Now()
	if cert.NotBefore.Before(time.Date(2013, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		cert.NotAfter.Before(now) {
		return nil, errors.New("Cert too old")
	}

	certList := make([]*x509.Certificate, 0)
	for _, certBytes := range ent.Entry.ExtraCerts {
		nextCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			continue
		}
		certList = append(certList, nextCert)
	}

	summary := CertSummary{}
	summary.CN = cert.Subject.CommonName
	summary.Issuer = cert.Issuer.CommonName
	summary.NotBefore = TimeToJSONString(cert.NotBefore)
	summary.NotAfter = TimeToJSONString(cert.NotAfter)
	summary.IsCA = cert.IsCA
	summary.Version = cert.Version
	summary.SignatureAlgorithm = int(cert.SignatureAlgorithm)
	summary.Violations = map[string]bool{
		VALID_PERIOD_TOO_LONG:          false,
		DEPRECATED_SIGNATURE_ALGORITHM: false,
		DEPRECATED_VERSION:             cert.Version != 3,
		KEY_TOO_SHORT:                  false,
		EXP_TOO_SMALL:                  false,
		MISSING_CN_IN_SAN:              false,
	}

	// BR 9.4.1: Validity period is longer than 5 years.  This
	// should be restricted to certs that don't have CA:True
	if cert.NotAfter.After(cert.NotBefore.AddDate(5, 0, 7)) &&
		(!cert.BasicConstraintsValid ||
			(cert.BasicConstraintsValid && !cert.IsCA)) {
		summary.Violations[VALID_PERIOD_TOO_LONG] = true
	}

	// SignatureAlgorithm is SHA1
	if cert.SignatureAlgorithm == x509.SHA1WithRSA ||
		cert.SignatureAlgorithm == x509.DSAWithSHA1 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {
		summary.Violations[DEPRECATED_SIGNATURE_ALGORITHM] = true
	}

	// Public key length <= 1024 bits
	summary.KeySize = -1
	summary.Exp = -1
	parsedKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if ok {
		summary.KeySize = parsedKey.N.BitLen()
		summary.Exp = parsedKey.E
		if summary.KeySize <= 1024 {
			summary.Violations[KEY_TOO_SHORT] = true
		}
		if summary.Exp <= 3 {
			summary.Violations[EXP_TOO_SMALL] = true
		}
	}

	if ranker != nil {
		summary.MaxReputation, _ = ranker.GetReputation(cert.Subject.CommonName)
		for _, host := range cert.DNSNames {
			reputation, _ := ranker.GetReputation(host)
			if reputation > summary.MaxReputation {
				summary.MaxReputation = reputation
			}
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

	summary.IssuerInMozillaDB = containsIssuerInRootList(certList, rootCAMap)

	// Assume a 0-length CN means it isn't present (this isn't a good
	// assumption). If the CN is missing, then it can't be missing CN in SAN.
	if len(cert.Subject.CommonName) == 0 {
		return &summary, nil
	}

	cnAsPunycode, err := idna.ToASCII(cert.Subject.CommonName)
	if err != nil {
		return &summary, nil
	}

	// BR 9.2.2: Found Common Name in Subject Alt Names, either as an IP or a
	// DNS name.
	summary.Violations[MISSING_CN_IN_SAN] = true
	cnAsIP := net.ParseIP(cert.Subject.CommonName)
	if cnAsIP != nil {
		for _, ip := range cert.IPAddresses {
			if cnAsIP.Equal(ip) {
				summary.Violations[MISSING_CN_IN_SAN] = false
			}
		}
	} else {
		for _, san := range cert.DNSNames {
			if err == nil && strings.EqualFold(san, cnAsPunycode) {
				summary.Violations[MISSING_CN_IN_SAN] = false
			}
		}
	}
	return &summary, nil
}

// Takes the name of a file containing newline-delimited Subject Common Names
// that each correspond to a certificate in Mozilla's root CA program.
// Returns these names as a map of string -> bool.
func ReadRootCAMap(filename string) map[string]bool {
	caStringBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open root CA list at %s: %s\n",
			filename, err)
		os.Exit(1)
	}
	rootCAMap := make(map[string]bool)
	for _, ca := range strings.Split(string(caStringBytes), "\n") {
		rootCAMap[ca] = true
	}
	return rootCAMap
}
