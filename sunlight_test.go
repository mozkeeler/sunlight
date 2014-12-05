package sunlight

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"github.com/monicachew/certificatetransparency"
	"testing"
	"time"
)

const pemCertificate = `-----BEGIN CERTIFICATE-----
MIIFxTCCBK2gAwIBAgIQBOTrHn+MUQnbvwwcf0EWkTANBgkqhkiG9w0BAQUFADBp
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSgwJgYDVQQDEx9EaWdpQ2VydCBIaWdoIEFzc3VyYW5j
ZSBFViBDQS0xMB4XDTEzMTIwMjAwMDAwMFoXDTE1MTIwNzEyMDAwMFowgf0xHTAb
BgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRMwEQYLKwYBBAGCNzwCAQMTAlVT
MRswGQYLKwYBBAGCNzwCAQITCkNhbGlmb3JuaWExETAPBgNVBAUTCEMyNTQzNDM2
MR4wHAYDVQQJExU2NTAgQ2FzdHJvIFN0IFN0ZSAzMDAxDjAMBgNVBBETBTk0MDQx
MQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZp
ZXcxGzAZBgNVBAoTEk1vemlsbGEgRm91bmRhdGlvbjEYMBYGA1UEAxMPd3d3Lm1v
emlsbGEub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuHHB4NGH
II28Vm4WrSFjZN5YM0bEBuVbPcwbwBAEinRe9Iwwwye359vVs24o5YRnSkjkJYfr
XHEb8f836GXBotN1xcxsrOi7brTJcA4qeE5ntby6V6wdlxKEy5mt2Fd9P7wl9v1U
lXmHyFxpF9UlDDoSuiDGUO+Q0U9lipKOrKoA3Q1Uzp/ntwrZL01BV4AUgTQf6b1H
Lu3ZD8CUG9xrq4Isi4OIMaJQX+kVwrQqxLe3Ahmjq9uP2iXAiLf7aVluTyFgfAfv
v1/pf0193zgQoe0oGDReh5/QrbO6j+XtV2sHDnDen+mQO2/GNwETfQPCIKIroGf4
JUnftt7Cwz1KmQIDAQABo4IB0jCCAc4wHwYDVR0jBBgwFoAUTFjLJfBBT1L0KMiB
Q5umqKDmkuUwHQYDVR0OBBYEFIPU1A81pLqLvmE3YsGWDTbHxzc5MCcGA1UdEQQg
MB6CD3d3dy5tb3ppbGxhLm9yZ4ILbW96aWxsYS5vcmcwDgYDVR0PAQH/BAQDAgWg
MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBjBgNVHR8EXDBaMCugKaAn
hiVodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vZXZjYTEtZzQuY3JsMCugKaAnhiVo
dHRwOi8vY3JsNC5kaWdpY2VydC5jb20vZXZjYTEtZzQuY3JsMEIGA1UdIAQ7MDkw
NwYJYIZIAYb9bAIBMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0
LmNvbS9DUFMwfQYIKwYBBQUHAQEEcTBvMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
cC5kaWdpY2VydC5jb20wRwYIKwYBBQUHMAKGO2h0dHA6Ly9jYWNlcnRzLmRpZ2lj
ZXJ0LmNvbS9EaWdpQ2VydEhpZ2hBc3N1cmFuY2VFVkNBLTEuY3J0MAwGA1UdEwEB
/wQCMAAwDQYJKoZIhvcNAQEFBQADggEBABnjOqDoPoJ/3K1W8+uxXLBzN27P31EI
9Qs2F9z4pB7flY6qR/XBBsECf/dVPd+xNJqqNKGwphNOycKApX/dy53QVf68YEnI
VvB4QzdWheZXl+1r+wlFfwpg0MT7Bdx1xvCd7D53HfPfFdan5/uhT8hns4wObgnn
w5DH5V9HDbhDHBEZg83Y2zmyki9J2EG8KpsvYEHNmmRok86OZe9NaSwwCK21kgMl
ilzypNybFK/PwCwWhytdsZTpvVp1SUCR6XYjD0BjzRJU8xB63N5HYgwl7cFS7yZL
upuIlUgiDZN7izlGZeqCM5mgBvnlYA0QcwdIpNy4S7JGp8KrhAW/0uo=
-----END CERTIFICATE-----`

func TestCertSummary(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(pemCertificate))
	//cert, _ := x509.ParseCertificate(pemBlock.Bytes)
	fakeRootCAMap := make(map[string]bool)
	//fakeCertList := make([]*x509.Certificate, 0)
	fakeList := [][]byte(nil)
	now := time.Now()
	ts := uint64(now.Unix())
	ct_entry := certificatetransparency.Entry{
		Timestamp:  ts,
		X509Cert:   pemBlock.Bytes,
		Time:       now,
		ExtraCerts: fakeList,
	}
	ent := certificatetransparency.EntryAndPosition{
		Entry: &ct_entry,
	}
	summary, err := CalculateCertSummary(&ent, nil, fakeRootCAMap)
	if err != nil {
		t.Errorf("Shouldn't have failed: %s\n", err)
	}
	expected := CertSummary{
		CN:                 "www.mozilla.org",
		Issuer:             "DigiCert High Assurance EV CA-1",
		Sha256Fingerprint:  "t1XI8b24uN+bPoKjhlRNRTb1rF/RuJlbd0fs+0tNtSc=",
		NotBefore:          "Dec 2 2013",
		NotAfter:           "Dec 7 2015",
		KeySize:            2048,
		Exp:                65537,
		SignatureAlgorithm: 3,
		Version:            3,
		IsCA:               false,
		DnsNames: []string{
			"www.mozilla.org",
			"mozilla.org",
		},
		IpAddresses: nil,
		Violations: map[string]bool{
			DEPRECATED_SIGNATURE_ALGORITHM: true,
			DEPRECATED_VERSION:             false,
			EXP_TOO_SMALL:                  false,
			KEY_TOO_SHORT:                  false,
			MISSING_CN_IN_SAN:              false,
			VALID_PERIOD_TOO_LONG:          false,
		},
		MaxReputation:     0,
		IssuerInMozillaDB: false,
		Timestamp:         ts,
	}

	b, _ := json.MarshalIndent(summary, "", "  ")
	expected_b, _ := json.MarshalIndent(expected, "", "  ")
	if !bytes.Equal(expected_b, b) {
		t.Errorf("Didn't get expected summary: %s \n!= \n%s\n", expected_b, b)
	}
}

func TestIssuerReputation(t *testing.T) {
	summary := CertSummary{
		CN:                "example.com",
		Issuer:            "Honest Al",
		Sha256Fingerprint: "foo",
		Violations: map[string]bool{
			VALID_PERIOD_TOO_LONG:          true,
			DEPRECATED_SIGNATURE_ALGORITHM: false,
			DEPRECATED_VERSION:             false,
			KEY_TOO_SHORT:                  false,
			EXP_TOO_SMALL:                  false,
			MISSING_CN_IN_SAN:              true,
		},
		MaxReputation:     0.1,
		IssuerInMozillaDB: false,
	}
	unknown_summary := CertSummary{
		CN:                "unknown.example.com",
		Issuer:            "Honest Al",
		Sha256Fingerprint: "foo",
		Violations: map[string]bool{
			VALID_PERIOD_TOO_LONG:          true,
			DEPRECATED_SIGNATURE_ALGORITHM: false,
			DEPRECATED_VERSION:             false,
			KEY_TOO_SHORT:                  false,
			EXP_TOO_SMALL:                  false,
			MISSING_CN_IN_SAN:              true,
		},
		IsCA:              false,
		MaxReputation:     -1,
		IssuerInMozillaDB: false,
	}
	issuer := NewIssuerReputation("Honest Al")
	issuer.Update(&summary)
	issuer.Update(&unknown_summary)
	issuer.Finish()
	if issuer.RawCount != 2 {
		t.Error("Should have raw count of 2")
	}
	if issuer.NormalizedCount != 1 {
		t.Error("Should have normalized count of 1")
	}
	if issuer.Scores[VALID_PERIOD_TOO_LONG].NormalizedScore != 0.9 {
		t.Error("Should have score of 0.9")
	}
	if issuer.IssuerInMozillaDB {
		t.Error("Should not be in mozilla db")
	}
	expected_issuer := IssuerReputation{
		Issuer: "Honest Al",
		Scores: map[string]*IssuerReputationScore{
			DEPRECATED_SIGNATURE_ALGORITHM: {
				NormalizedScore: 1,
				RawScore:        1,
			},
			DEPRECATED_VERSION: {
				NormalizedScore: 1,
				RawScore:        1,
			},
			EXP_TOO_SMALL: {
				NormalizedScore: 1,
				RawScore:        1,
			},
			KEY_TOO_SHORT: {
				NormalizedScore: 1,
				RawScore:        1,
			},
			MISSING_CN_IN_SAN: {
				NormalizedScore: 0.9,
				RawScore:        0,
			},
			VALID_PERIOD_TOO_LONG: {
				NormalizedScore: 0.9,
				RawScore:        0,
			},
		},
		IsCA:            0,
		NormalizedScore: 0.9666667,
		RawScore:        0.6666667,
		NormalizedCount: 1,
		RawCount:        2,
	}
	b, _ := json.MarshalIndent(issuer, "", "  ")
	expected_b, _ := json.MarshalIndent(expected_issuer, "", "  ")
	if !bytes.Equal(expected_b, b) {
		t.Errorf("Didn't get expected reputation: %s \n!= \n%s\n", expected_b, b)
	}
}
