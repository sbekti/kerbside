# Releasing

The release workflow builds an ad hoc signed app, creates a draft GitHub Release,
and opens a cask pull request in `sbekti/homebrew-tap`.

## Configuration

The GitHub environment `release` requires:

| Name | Type | Purpose |
| --- | --- | --- |
| `HOMEBREW_PUBLISHER_CLIENT_ID` | Variable | Homebrew publisher GitHub App client ID |
| `HOMEBREW_PUBLISHER_PRIVATE_KEY` | Secret | Publisher App private key |

Install the App on `sbekti/homebrew-tap` with contents and pull-request write
permissions. The workflow restricts its token to that repository. The standard
`GITHUB_TOKEN` writes the Kerbside draft release. Pull-request builds do not use
publisher credentials or AD credentials.

## Procedure

1. Verify the build, tests, and disposable-keychain probe pass.
2. Complete [real-account and FileVault verification](TESTING.md).
3. Tag the reviewed commit, for example `v0.1.0`.
4. Review the draft release archive and generated cask. Publish the release
   before merging the tap pull request so the download URL is available.
5. Verify installation and upgrade through the tap on the test Mac.

The cask version and SHA-256 are derived from the release archive. To render it
locally:

```bash
python3 scripts/cask.py 0.1.0 build/dist/Kerbside-0.1.0-arm64.zip
```

Builds are not Developer ID signed or notarized. The cask preserves macOS
quarantine and Gatekeeper checks.
