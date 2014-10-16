package main

import (
	"code.google.com/p/go.net/idna"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/monicachew/certificatetransparency"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func timeToJSONString(t time.Time) string {
	const layout = "Jan 2 2006"
	return t.Format(layout)
}

func main() {
	fmt.Fprintf(os.Stderr, "testing go fmt pre-commit hook")
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <log entries file> [uint64 max_entries_to_read]\n", os.Args[0])
		os.Exit(1)
	}
	fileName := os.Args[1]
	// No limit on entries read
	var limit uint64 = 0
	if len(os.Args) == 3 {
		limit, _ = strconv.ParseUint(os.Args[2], 0, 64)
	}

	now := time.Now()
	fmt.Fprintf(os.Stderr, "Starting %s\n", time.Now())
	in, err := os.Open(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open entries file: %s\n", err)
		os.Exit(1)
	}
	defer in.Close()

	entriesFile := certificatetransparency.EntriesFile{in}
	fmt.Fprintf(os.Stderr, "Initialized entries %s\n", time.Now())

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
	}

	fmt.Fprintf(os.Stdout, "{\"Certs\":[")
	firstOutLock := new(sync.Mutex)
	firstOut := true

	entriesFile.Map(func(ent *certificatetransparency.EntryAndPosition, err error) {
		if err != nil {
			return
		}

		cert, err := x509.ParseCertificate(ent.Entry.X509Cert)
		if err != nil {
			return
		}

		// Assume a 0-length CN means it isn't present (this isn't a good assumption)
		if len(cert.Subject.CommonName) == 0 {
			return
		}

		// Filter out certs issued before 2013 or that have already
		// expired.
		if cert.NotBefore.Before(time.Date(2013, 1, 1, 0, 0, 0, 0, time.UTC)) ||
			cert.NotAfter.Before(now) {
			return
		}

		cnAsPunycode, error := idna.ToASCII(cert.Subject.CommonName)
		if error != nil {
			return
		}

		// BR 9.2.2: Found Common Name in Subject Alt Names, either as an IP or a
		// DNS name.
		missingCNinSAN := true
		cnAsIP := net.ParseIP(cert.Subject.CommonName)
		if cnAsIP != nil {
			for _, ip := range cert.IPAddresses {
				if cnAsIP.Equal(ip) {
					missingCNinSAN = false
				}
			}
		} else {
			for _, san := range cert.DNSNames {
				if error == nil && strings.EqualFold(san, cnAsPunycode) {
					missingCNinSAN = false
				}
			}
		}

		// BR 9.4.1: Validity period is longer than 5 years.  This
		// should be restricted to certs that don't have CA:True
		validPeriodTooLong := false
		if cert.NotAfter.After(cert.NotBefore.AddDate(5, 0, 7)) &&
			(!cert.BasicConstraintsValid || (cert.BasicConstraintsValid && !cert.IsCA)) {
			validPeriodTooLong = true
		}

		// SignatureAlgorithm is SHA1
		deprecatedSignatureAlgorithm := false
		if cert.SignatureAlgorithm == x509.SHA1WithRSA ||
			cert.SignatureAlgorithm == x509.DSAWithSHA1 ||
			cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {
			deprecatedSignatureAlgorithm = true
		}

		// Uses v1 certificates
		deprecatedVersion := cert.Version != 3

		// Public key length <= 1024 bits
		keyTooShort := false
		expTooSmall := false
		keySize := -1
		exp := -1
		parsedKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if ok {
			keySize = parsedKey.N.BitLen()
			exp = parsedKey.E
			if keySize <= 1024 {
				keyTooShort = true
			}
			if exp <= 3 {
				expTooSmall = true
			}
		}

		if missingCNinSAN || validPeriodTooLong || deprecatedSignatureAlgorithm ||
			deprecatedVersion || keyTooShort || expTooSmall {
			sha256hasher := sha256.New()
			sha256hasher.Write(cert.Raw)
			summary := CertSummary{
				CN:                           cert.Subject.CommonName,
				Issuer:                       cert.Issuer.CommonName,
				Sha256Fingerprint:            base64.StdEncoding.EncodeToString(sha256hasher.Sum(nil)),
				NotBefore:                    timeToJSONString(cert.NotBefore.Local()),
				NotAfter:                     timeToJSONString(cert.NotAfter.Local()),
				ValidPeriodTooLong:           validPeriodTooLong,
				DeprecatedSignatureAlgorithm: deprecatedSignatureAlgorithm,
				DeprecatedVersion:            deprecatedVersion,
				MissingCNinSAN:               missingCNinSAN,
				KeyTooShort:                  keyTooShort,
				KeySize:                      keySize,
				ExpTooSmall:                  expTooSmall,
				Exp:                          exp,
				SignatureAlgorithm:           int(cert.SignatureAlgorithm),
				Version:                      cert.Version,
				IsCA:                         cert.BasicConstraintsValid && cert.IsCA,
				DnsNames:                     cert.DNSNames,
				IpAddresses:                  nil,
			}
			for _, address := range cert.IPAddresses {
				summary.IpAddresses = append(summary.IpAddresses, address.String())
			}
			marshalled, err := json.Marshal(summary)
			if err == nil {
				separator := ",\n"
				firstOutLock.Lock()
				if firstOut {
					separator = "\n"
				}
				fmt.Fprintf(os.Stdout, "%s", separator)
				os.Stdout.Write(marshalled)
				firstOut = false
				firstOutLock.Unlock()
			} else {
				fmt.Fprintf(os.Stderr, "Couldn't write json: %s\n", err)
				os.Exit(1)
			}
		}
	}, limit)
	fmt.Fprintf(os.Stdout, "]}\n")
}
