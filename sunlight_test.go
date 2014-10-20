package sunlight

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
)

const pemCertificate = `-----BEGIN CERTIFICATE-----
MIIB5DCCAZCgAwIBAgIBATALBgkqhkiG9w0BAQUwLTEQMA4GA1UEChMHQWNtZSBDbzEZMBcGA1UE
AxMQdGVzdC5leGFtcGxlLmNvbTAeFw03MDAxMDEwMDE2NDBaFw03MDAxMDIwMzQ2NDBaMC0xEDAO
BgNVBAoTB0FjbWUgQ28xGTAXBgNVBAMTEHRlc3QuZXhhbXBsZS5jb20wWjALBgkqhkiG9w0BAQED
SwAwSAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0fd7Ai2KW5ToIwzFo
fvJcS/STa6HA5gQenRUCAwEAAaOBnjCBmzAOBgNVHQ8BAf8EBAMCAAQwDwYDVR0TAQH/BAUwAwEB
/zANBgNVHQ4EBgQEAQIDBDAPBgNVHSMECDAGgAQBAgMEMBsGA1UdEQQUMBKCEHRlc3QuZXhhbXBs
ZS5jb20wDwYDVR0gBAgwBjAEBgIqAzAqBgNVHR4EIzAhoB8wDoIMLmV4YW1wbGUuY29tMA2CC2V4
YW1wbGUuY29tMAsGCSqGSIb3DQEBBQNBAHKZKoS1wEQOGhgklx4+/yFYQlnqwKXvar/ZecQvJwui
0seMQnwBhwdBkHfVIU2Fu5VUMRyxlf0ZNaDXcpU581k=
-----END CERTIFICATE-----`

func TestCertSummary(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(pemCertificate))
	cert, _ := x509.ParseCertificate(pemBlock.Bytes)
	summary, _ := CalculateCertSummary(cert, nil)
	expected := CertSummary{
		CN:                 "test.example.com",
		Issuer:             "test.example.com",
		Sha256Fingerprint:  "Gvp+Qw6i96YPjUZoO2zqLWdusngA8xpAtvMBouj+MZ8=",
		NotBefore:          "Jan 1 1970",
		NotAfter:           "Jan 2 1970",
		KeySize:            512,
		Exp:                65537,
		SignatureAlgorithm: 3,
		Version:            3,
		IsCA:               true,
		DnsNames:           []string{"test.example.com"},
		IpAddresses:        nil,
		Violations: map[string]bool{
			"DeprecatedSignatureAlgorithm": true,
			"DeprecatedVersion":            false,
			"ExpTooSmall":                  false,
			"KeyTooShort":                  true,
			"MissingCNInSan":               false,
			"ValidPeriodTooLong":           false,
		},
		MaxReputation: 0,
	}
	b, _ := json.MarshalIndent(summary, "", "  ")
	expected_b, _ := json.MarshalIndent(expected, "", "  ")
	if !bytes.Equal(expected_b, b) {
		t.Errorf("Didn't get expected summary: %b \n!= \n%b\n", expected_b, b)
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
		MaxReputation: 0.1,
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
		IsCA:          false,
		MaxReputation: -1,
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
	b, _ := json.MarshalIndent(issuer, "", "  ")
	os.Stderr.Write(b)
}
