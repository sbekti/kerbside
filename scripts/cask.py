#!/usr/bin/env python3
"""Render the cask from the actual release archive, never a placeholder hash."""
import hashlib
from pathlib import Path
import re
import sys

version, archive = sys.argv[1:]
if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', version):
    raise SystemExit('Invalid release version')
checksum = hashlib.sha256(Path(archive).read_bytes()).hexdigest()
print('''cask "kerbside" do
  version "%s"
  sha256 "%s"

  url "https://github.com/sbekti/kerbside/releases/download/v#{version}/Kerbside-#{version}-arm64.zip"
  name "Kerbside"
  desc "Small Active Directory companion for the macOS menu bar"
  homepage "https://github.com/sbekti/kerbside"

  depends_on arch: :arm64
  depends_on macos: ">= 27.0"

  app "Kerbside.app"

  caveats <<~EOS
    Experimental: validate password sync and FileVault with a test account first.
    This build is ad hoc signed, not notarized. macOS may require first-open approval.
    Open Kerbside to configure your AD account; no domain join is performed.
  EOS
end
''' % (version, checksum))
