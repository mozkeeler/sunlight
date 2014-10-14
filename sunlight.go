package main

import (
	"code.google.com/p/go.net/idna"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/monicachew/certificatetransparency"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func timeToJSONString(t time.Time) string {
	const layout = "Jan 2 2006"
	return t.Format(layout)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <log entries file>\n", os.Args[0])
		os.Exit(1)
	}
	fileName := os.Args[1]

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

	outputLock := new(sync.Mutex)

	//fmt.Print("{ \"certs\": [\n")
	firstEntry := true
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

		// Filter out certs issued before 2014 or that have already expired.
		if cert.NotBefore.Before(time.Date(2014, 1, 1, 0, 0, 0, 0, time.UTC)) ||
			cert.NotAfter.Before(now) {
			return
		}

		cnAsPunycode, error := idna.ToASCII(cert.Subject.CommonName)
		if error != nil {
			return
		}

		// BR 9.2.2: Found Common Name in Subject Alt Names, either as an IP or a
		// DNS name.
		foundCNinSAN := false
		cnAsIP := net.ParseIP(cert.Subject.CommonName)
		if cnAsIP != nil {
			for _, ip := range cert.IPAddresses {
				if cnAsIP.Equal(ip) {
					foundCNinSAN = true
				}
			}
		} else {
			for _, san := range cert.DNSNames {
				if error == nil && strings.EqualFold(san, cnAsPunycode) {
					foundCNinSAN = true
				}
			}
		}

		// BR 9.4.1: Validity period is longer than 60 months and issued after
		// 2014 (really should be 1 July 2012).
		validPeriodTooLong := false
		if cert.NotBefore.AddDate(0, 60, 0).After(cert.NotAfter) {
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
		deprecatedVersion := cert.Version == 1

		if !foundCNinSAN || validPeriodTooLong || deprecatedSignatureAlgorithm ||
			deprecatedVersion {
			outputLock.Lock()
			if !firstEntry {
				fmt.Printf(",")
			}

			firstEntry = false
			fmt.Printf("\n  {")
			fmt.Printf("\n    \"cn\": \"%s\",", cert.Subject.CommonName)
			fmt.Printf("\n    \"issuer\": \"%s\",", cert.Issuer.CommonName)
			sha256hasher := sha256.New()
			sha256hasher.Write(cert.Raw)
			fmt.Printf("\n    \"sha256Fingerprint\": \"%s\",", base64.StdEncoding.EncodeToString(sha256hasher.Sum(nil)))
			fmt.Printf("\n    \"notBefore\": \"%s\",", timeToJSONString(cert.NotBefore.Local()))
			fmt.Printf("\n    \"notAfter\": \"%s\",", timeToJSONString(cert.NotAfter.Local()))
			fmt.Printf("\n    \"validPeriodTooLong\": \"%t\",", validPeriodTooLong)
			fmt.Printf("\n    \"deprecatedSignatureAlgorithm\": \"%s\",", deprecatedSignatureAlgorithm)
			fmt.Printf("\n    \"deprecatedVersion\": \"%t\",", deprecatedVersion)
			fmt.Printf("\n    \"foundCNinSAN\": \"%t\",", foundCNinSAN)
			fmt.Printf("\n    \"signatureAlgorithm\": \"%d\",", cert.SignatureAlgorithm)
			fmt.Printf("\n    \"version\": \"%d\",", cert.Version)
			fmt.Printf("\n    \"dnsNames\": [")
			firstName := true
			for _, san := range cert.DNSNames {
				if !firstName {
					fmt.Printf(",")
				}
				firstName = false
				fmt.Printf("\n      \"%s\"", san)
			}
			fmt.Printf("\n    ],")

			fmt.Printf("\n    \"ipAddresses\": [")
			firstAddress := true
			for _, address := range cert.IPAddresses {
				if !firstAddress {
					fmt.Printf(",")
				}
				firstAddress = false
				fmt.Printf("\n      \"%s\"", address.String())
			}
			fmt.Printf("\n    ]")
			fmt.Printf("\n  }")
			outputLock.Unlock()
		}
	})
	fmt.Print("\n]\n")
	//fmt.Print("}\n")
}
