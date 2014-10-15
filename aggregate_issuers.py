#!/usr/bin/python
"""Create a CSV file from the JSON output of sunlight.go."""

import json
import os
import sys
import codecs


def main():
  if len(sys.argv) != 3:
    sys.exit("Usage: " + sys.argv[0] + " <certs.json> <output_file.csv>")

  f_in = open(sys.argv[1], "r")
  #f_out = codecs.open(sys.argv[2], "w", encoding='utf8')
  f_out = open(sys.argv[2], "w")
  blob = json.loads(f_in.read())

  certs = blob["Certs"]

  issuers = {};
  for c in certs:
    issuer = c["Issuer"]
    if not issuer in issuers:
      issuers[issuer] = { "DeprecatedVersion": 0,
                          "ExpTooSmall": 0,
                          "IsCA": 0,
                          "KeyTooShort": 0,
                          "MissingCNinSAN": 0,
                          "ValidPeriodTooLong": 0 }
    if c["DeprecatedVersion"]:
      issuers[issuer]["DeprecatedVersion"] += 1
    if c["ExpTooSmall"]:
      issuers[issuer]["ExpTooSmall"] += 1
    if c["IsCA"]:
      issuers[issuer]["IsCA"] += 1
    if c["KeyTooShort"]:
      issuers[issuer]["KeyTooShort"] += 1
    if c["MissingCNinSAN"]:
      issuers[issuer]["MissingCNinSAN"] += 1
    if c["ValidPeriodTooLong"]:
      issuers[issuer]["ValidPeriodTooLong"] += 1

  f_out.write("issuer,deprecatedVersion,expTooSmall,isCA,keyTooShort,missingCNinSAN,validPeriodTooLong,n_violations\n");
  for issuer in issuers:
    n_violations = (issuers[issuer]["DeprecatedVersion"] +
          issuers[issuer]["ExpTooSmall"] +
          issuers[issuer]["KeyTooShort"] +
          issuers[issuer]["MissingCNinSAN"] +
          issuers[issuer]["ValidPeriodTooLong"])
    f_out.write("%s,%d,%d,%d,%d,%d,%d,%d\n" % (
                issuer.encode('utf-8'),
                issuers[issuer]["DeprecatedVersion"],
                issuers[issuer]["ExpTooSmall"],
                issuers[issuer]["IsCA"],
                issuers[issuer]["KeyTooShort"],
                issuers[issuer]["MissingCNinSAN"],
                issuers[issuer]["ValidPeriodTooLong"], n_violations));

if __name__ == "__main__":
  main()
