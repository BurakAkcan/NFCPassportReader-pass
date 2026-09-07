#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
framework_dir="$PWD/.build/artifacts/openssl-package/OpenSSL/OpenSSL.xcframework/macos-arm64_x86_64"
if [[ ! -d "$framework_dir/OpenSSL.framework" ]]; then
  echo "Resolve package dependencies first: swift package resolve" >&2
  exit 1
fi
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT
# Errors.swift uses this existing helper; the remaining Utils.swift code is not needed here.
sed -n '/^extension Int {/,/^}/p' Sources/NFCPassportReader/Utils.swift > "$test_dir/IntExtension.swift"
swiftc Sources/NFCPassportReader/LDSSecurityObjectParser.swift \
  Sources/NFCPassportReader/DataGroups/DataGroupId.swift \
  Sources/NFCPassportReader/Errors.swift \
  RegressionTests/SODParserTests.swift "$test_dir/IntExtension.swift" \
  -F "$framework_dir" -framework OpenSSL \
  -Xlinker -rpath -Xlinker "$framework_dir" -o "$test_dir/SODParserTests"
"$test_dir/SODParserTests"
