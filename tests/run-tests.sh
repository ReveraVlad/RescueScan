#!/bin/sh
# Builds RescueScan.cs + tests/RescueScan.Tests.cs with Mono in strict C# 5 mode and runs the tests.
# Registry tests use Mono's registry emulation (~/.mono/registry); the throwaway test key is removed afterwards.
# Tests marked [win] (P/Invoke, reg.exe, registry links) are skipped here: run tests/run-tests.ps1 on Windows.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
out=$(mktemp -d "${TMPDIR:-/tmp}/rescuescan-tests.XXXXXX")
trap 'rm -rf "$out"' EXIT
mcs -langversion:5 -warn:4 -target:exe -main:RescueScan.Tests.TestMain -out:"$out/RescueScan.Tests.exe" \
    -r:System.Windows.Forms.dll -r:System.Drawing.dll -r:System.Core.dll -r:System.Management.dll \
    "$root/RescueScan.cs" "$here/RescueScan.Tests.cs"
LANG=C.UTF-8 LC_ALL=C.UTF-8 mono "$out/RescueScan.Tests.exe"
