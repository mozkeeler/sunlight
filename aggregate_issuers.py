#!/usr/bin/python
"""Create a CSV file from the JSON output of sunlight.go."""

import json
import os
import sys


def main():
  if len(sys.argv) != 3:
    sys.exit("Usage: " + sys.argv[0] + " <certs.json> <output_file.csv>")

  f_in = open(sys.argv[1], "r")
  f_out = open(sys.argv[2], "w")
  blob = json.loads(f_in.read())

  certs = blob["certs"]

  issuers = {};
  for c in certs:
    issuer = c.issuer
    if not issuers[issuer]:
      issuers[issuer] = { "DeprecatedVersion": 0,
                          "ExpTooSmall": 0,
                          "IsCA": 0,
                          "KeyTooShort": 0,
                          "MissingCNinSAN": 0,
                          "ValidPeriodTooLong": 0 }
    if c.deprecatedVersion:
      issuers[issuer]["DeprecatedVersion"] += 1
    if c.expTooSmall:
      issuers[issuer]["ExpTooSmall"] += 1
    if c.isCA:
      issuers[issuer]["IsCA"] += 1
    if c.keyTooShort:
      issuers[issuer]["KeyTooShort"] += 1
    if c.missingCNinSAN:
      issuers[issuer]["MissingCNinSAN"] += 1
    if c.validPeriodTooLong:
      issuers[issuer]["ValidPeriodTooLong"] += 1

  f_out.write("issuer,deprecatedVersion,expTooSmall,isCA,keyTooShort,missingCNinSAN,validPeriodTooLong\n");
  for issuer in issuers:
    f_out.write("%s,%d,%d,%d,%d,%d,%d\n",
                issuer,
                issuers[issuer]["DeprecatedVersion"],
                issuers[issuer]["ExpTooSmall"],
                issuers[issuer]["IsCA"],
                issuers[issuer]["KeyTooShort"],
                issuers[issuer]["MissingCNinSAN"],
                issuers[issuer]["ValidPeriodTooLong"]);

if __name__ == "__main__":
  main()
