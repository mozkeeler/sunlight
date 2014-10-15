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
      issuers[issuer] = { "deprecatedVersion": 0,
                          "expTooSmall": 0,
                          "isCA": 0,
                          "keyTooShort": 0,
                          "missingCNinSAN": 0,
                          "validPeriodTooLong": 0 }
    if c.deprecatedVersion:
      issuers[issuer]["deprecatedVersion"] += 1
    if c.expTooSmall:
      issuers[issuer]["expTooSmall"] += 1
    if c.isCA:
      issuers[issuer]["isCA"] += 1
    if c.keyTooShort:
      issuers[issuer]["keyTooShort"] += 1
    if c.missingCNinSAN:
      issuers[issuer]["missingCNinSAN"] += 1
    if c.validPeriodTooLong:
      issuers[issuer]["validPeriodTooLong"] += 1

  f_out.write("issuer,deprecatedVersion,expTooSmall,isCA,keyTooShort,missingCNinSAN,validPeriodTooLong\n");
  for issuer in issuers:
    f_out.write("%s,%d,%d,%d,%d,%d,%d\n",
                issuer,
                issuers[issuer]["deprecatedVersion"],
                issuers[issuer]["expTooSmall"],
                issuers[issuer]["isCA"],
                issuers[issuer]["keyTooShort"],
                issuers[issuer]["missingCNinSAN"],
                issuers[issuer]["validPeriodTooLong"]);

if __name__ == "__main__":
  main()
