package sunlight

import (
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
	pemBlock, _ := pem.Decode([]byte(pemCertificate)
	cert, err := ParseCertificate(pemBlock.Bytes)
  summary := CalculateCertSummary(&cert, nil)
	if summary.ValidPeriodTooLong {
		t.Error("Valid period too long\n")
	}
}

func TestIssuerReputation(t *testing.T) {
	summary := CertSummary{
		CN:                           "example.com",
		Issuer:                       "Honest Al",
		Sha256Fingerprint:            "foo",
		ValidPeriodTooLong:           true,
		DeprecatedSignatureAlgorithm: false,
		DeprecatedVersion:            false,
		MissingCNinSAN:               true,
		KeyTooShort:                  false,
		ExpTooSmall:                  false,
		IsCA:                         false,
		MaxReputation:                0.1,
	}
	unknown_summary := CertSummary{
		CN:                           "unknown.example.com",
		Issuer:                       "Honest Al",
		Sha256Fingerprint:            "foo",
		ValidPeriodTooLong:           true,
		DeprecatedSignatureAlgorithm: false,
		DeprecatedVersion:            false,
		MissingCNinSAN:               true,
		KeyTooShort:                  false,
		ExpTooSmall:                  false,
		IsCA:                         false,
		MaxReputation:                -1,
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
	if issuer.ValidPeriodTooLong.NormalizedScore != 0.9 {
		t.Error("Should have score of 0.1")
	}
	b, _ := json.MarshalIndent(issuer, "", "  ")
	os.Stderr.Write(b)
}
