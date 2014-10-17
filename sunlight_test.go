package sunlight

import "testing"
import "os"
import "encoding/json"

func TestInit(t *testing.T) {
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
	if issuer.ValidPeriodTooLong.NormalizedScore != 0.1 {
		t.Error("Should have score of 0.1")
	}
	b, _ := json.MarshalIndent(issuer, "", "  ")
	os.Stderr.Write(b)
}
