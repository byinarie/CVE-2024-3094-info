#!/bin/bash

# script to detect CVE-2024-3094

# original script:
# https://www.openwall.com/lists/oss-security/2024/03/29/4

# modified (fixed and features added) by cyclone
# https://github.com/cyclone-github/scripts/blob/main/xz_cve-2024-3094-detect.sh

# tested on debian

# https://nvd.nist.gov/vuln/detail/CVE-2024-3094
# https://github.com/advisories/GHSA-rxwq-x6h5-x525

# v1.0.0; 2024-03-29

set -eu

clear

echo "Checking system for CVE-2024-3094 Vulnerability..."
echo "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"

# find path to liblzma used by sshd
# adapted from https://www.openwall.com/lists/oss-security/2024/03/29/4
sshd_path=$(whereis -b sshd | awk '{print $2}')
path=$(ldd "$sshd_path" 2>/dev/null | grep liblzma | awk '{print $3}' | head -n 1)

if [ -z "$path" ]; then
    echo
    echo "Probably not vulnerable (liblzma not found)"
    exit
fi

# check for function signature
# adapted from https://www.openwall.com/lists/oss-security/2024/03/29/4
echo
echo "Checking for function signature in liblzma..."
if hexdump -ve '1/1 "%.2x"' "$path" | grep -q 'f30f1efa554889f54c89ce5389fb81e7000000804883ec28488954241848894c2410'; then
    echo "Function signature in liblzma: VULNERABLE"
else
    echo "Function signature in liblzma: OK"
fi

# check xz version
xz_version=$(xz --version | head -n1 | awk '{print $4}')
pwn_version="5.6.0"
echo
echo "Checking xz version..."
if [[ "$(printf '%s\n' "$xz_version" "$pwn_version" | sort -V | head -n1)" == "$pwn_version" ]]; then
    echo "xz version $xz_version: VULNERABLE"
else
    echo "xz version $xz_version: OK"
fi
