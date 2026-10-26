#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:-0.1.0}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
  echo 'Expected a version such as 0.1.0 or 0.1.0-preview.1' >&2
  exit 1
fi
xcodebuild -project Kerbside.xcodeproj -scheme Kerbside -configuration Release \
  -derivedDataPath build -destination 'generic/platform=macOS' \
  MARKETING_VERSION="${version%%-*}" CURRENT_PROJECT_VERSION="${GITHUB_RUN_NUMBER:-1}" build
app="build/Build/Products/Release/Kerbside.app"
codesign --verify --strict "$app"
mkdir -p build/dist
ditto -c -k --sequesterRsrc --keepParent "$app" "build/dist/Kerbside-${version}-arm64.zip"
shasum -a 256 "build/dist/Kerbside-${version}-arm64.zip"
