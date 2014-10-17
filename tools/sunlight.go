package main

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/monicachew/alexa"
	"github.com/monicachew/certificatetransparency"
	"github.com/mozkeeler/sunlight"
	"os"
	"runtime"
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
	runtime.GOMAXPROCS(runtime.NuMCPUS())
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

		summary, _ := sunlight.CalculateCertSummary(cert, &ranker)
		if summary != nil && summary.ViolatesBR() {
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
