package main

import (
	"code.google.com/p/go.net/idna"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/monicachew/alexa"
	"github.com/monicachew/certificatetransparency"
	"net"
	"os"
	"strings"
	"github.com/mozkeeler/sunlight"
	"sync"
	"time"
)

// Flags
var alexaFile string
var dbFile string
var ctLog string
var jsonFile string
var maxEntries uint64

func init() {
	flag.StringVar(&alexaFile, "alexa_file", "top-1m.csv",
		"CSV containing <rank, domain>")
	flag.StringVar(&dbFile, "db_file", "BRs.db", "File for creating sqlite DB")
	flag.StringVar(&ctLog, "ct_log", "ct_entries.log", "File containing CT log")
	flag.StringVar(&jsonFile, "json_file", "certs.json", "JSON summary output")
	flag.Uint64Var(&maxEntries, "max_entries", 0, "Max entries (0 means all)")
}

func main() {
	flag.Parse()
	if flag.NArg() != 0 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	var ranker alexa.AlexaRank
	ranker.Init(alexaFile)
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open %s: %s\n", dbFile, err)
		flag.PrintDefaults()
		os.Exit(1)
	}
	defer db.Close()

	createTables := `
  drop table if exists baselineRequirements;
  create table baselineRequirements (cn text, issuer text,
                                     sha256Fingerprint text, notBefore date,
                                     notAfter date, validPeriodTooLong bool,
                                     deprecatedSignatureAlgorithm bool,
                                     deprecatedVersion bool,
                                     missingCNinSAN bool, keyTooShort bool,
                                     keySize integer, expTooSmall bool,
                                     exp integer, signatureAlgorithm integer,
                                     version integer, dnsNames string,
                                     ipAddresses string, maxReputation float);
  `

	_, err = db.Exec(createTables)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create table: %s\n", err)
		os.Exit(1)
	}

	tx, err := db.Begin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to begin using DB: %s\n", err)
		os.Exit(1)
	}

	insertEntry := `
  insert into baselineRequirements(cn, issuer, sha256Fingerprint, notBefore,
                                   notAfter, validPeriodTooLong,
                                   deprecatedSignatureAlgorithm,
                                   deprecatedVersion, missingCNinSAN,
                                   keyTooShort, keySize, expTooSmall, exp,
                                   signatureAlgorithm, version, dnsNames,
                                   ipAddresses, maxReputation)
              values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
	insertEntryStatement, err := tx.Prepare(insertEntry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create prepared statement: %s\n", err)
		os.Exit(1)
	}
	defer insertEntryStatement.Close()

	now := time.Now()
	fmt.Fprintf(os.Stderr, "Starting %s\n", time.Now())
	in, err := os.Open(ctLog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open entries file: %s\n", err)
		flag.PrintDefaults()
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

	out, err := os.OpenFile(jsonFile, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open JSON output file %s: %s\n",
			jsonFile, err)
		flag.PrintDefaults()
	}

	fmt.Fprintf(out, "{\"Certs\":[")
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

		maxReputation, _ := ranker.GetReputation(cert.Subject.CommonName)
		for _, host := range cert.DNSNames {
			reputation, _ := ranker.GetReputation(host)
			if reputation > maxReputation {
				maxReputation = reputation
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
				NotBefore:                    sunlight.TimeToJSONString(cert.NotBefore.Local()),
				NotAfter:                     sunlight.TimeToJSONString(cert.NotAfter.Local()),
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
				MaxReputation:                maxReputation,
			}
			for _, address := range cert.IPAddresses {
				summary.IpAddresses = append(summary.IpAddresses, address.String())
			}
			dnsNamesAsString, err := json.Marshal(summary.DnsNames)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to convert to JSON: %s\n", err)
				os.Exit(1)
			}
			ipAddressesAsString, err := json.Marshal(summary.IpAddresses)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to convert to JSON: %s\n", err)
				os.Exit(1)
			}
			_, err = insertEntryStatement.Exec(summary.CN, summary.Issuer,
				summary.Sha256Fingerprint,
				cert.NotBefore, cert.NotAfter,
				summary.ValidPeriodTooLong,
				summary.DeprecatedSignatureAlgorithm,
				summary.DeprecatedVersion,
				summary.MissingCNinSAN,
				summary.KeyTooShort, summary.KeySize,
				summary.ExpTooSmall, summary.Exp,
				summary.SignatureAlgorithm,
				summary.Version, dnsNamesAsString,
				ipAddressesAsString,
				summary.MaxReputation)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to insert entry: %s\n", err)
				os.Exit(1)
			}
			marshalled, err := json.Marshal(summary)
			if err == nil {
				separator := ",\n"
				firstOutLock.Lock()
				if firstOut {
					separator = "\n"
				}
				fmt.Fprintf(out, "%s", separator)
				out.Write(marshalled)
				firstOut = false
				firstOutLock.Unlock()
			} else {
				fmt.Fprintf(os.Stderr, "Couldn't write json: %s\n", err)
				os.Exit(1)
			}
		}
	}, maxEntries)
	tx.Commit()
	fmt.Fprintf(out, "]}\n")
}