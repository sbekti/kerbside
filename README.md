# Kerbside

A native macOS menu bar app for Active Directory authentication, Kerberos
tickets, and password sync with an existing local account. Adapted from
[NoMAD](https://github.com/jamf/NoMAD).

**Experimental:** password sync uses an
[unsupported keychain function](https://developer.apple.com/forums/thread/821894).
Test with a dedicated account before daily use. CI checks do not validate
real-account login or FileVault unlock; see [verification](docs/TESTING.md).

## Setup

Requires Apple silicon, macOS 27, and access to your AD network, directly or
through a VPN. No domain join, AD administrator, or new Mac account is required.

1. Open Kerbside and enter your AD DNS domain, such as `ad.example.com`, and username.
2. Sign in with your AD password. Kerbside discovers controllers through macOS
   scoped DNS, obtains a Kerberos ticket, and uses it for certificate-validated LDAPS.
3. Choose **Sync Password** to align the current Mac account and login keychain
   with AD, or cancel and sync later. **Launch at login** is optional.

The menu shows connection, ticket, and password-expiry information, with actions
to sign in, renew tickets, sync or change passwords, and sign out.

## Password behavior

AD is the password authority. Kerbside checks `pwdLastSet` about every 15 minutes
while connected, and after wake or network changes. A detected change prompts
for sign-in; AD cannot supply the new password itself. Failed authentication
pauses automatic attempts until an explicit sign-in.

| Action | Result |
| --- | --- |
| Change Password in Kerbside | Changes AD first, then the local account and login keychain. Partial failures are reported. |
| Change AD elsewhere | A later directory check detects the change. Sign in with the new password and sync. |
| Change the Mac password in System Settings or `passwd` | Changes the local account, not AD. Explicit sync aligns it with AD again; command-line changes may also require keychain repair. |
| Disconnect from AD | Local login and FileVault continue using the last successfully set local password. |

Sync verifies the AD credential before changing the Mac password. If the local
update succeeds but the keychain update fails, **Repair Login Keychain** requests
the current Mac password and previous keychain password. It preserves saved items
and never resets the keychain. Completed AD changes are not rolled back automatically.

The AD credential is stored in the login Keychain. Settings and change timestamps
are stored in `com.bekti.kerbside` preferences. The Mac/keychain password entered
for sync is not stored separately. When passwords match, the saved AD credential
also matches the Mac password. Sign Out removes that credential and the configured
principal's tickets.

## Build and test

Requires Xcode 27 and the macOS 27 SDK. The checked-in Xcode project has no
third-party build or runtime dependencies.

```bash
xcodebuild -project Kerbside.xcodeproj -scheme Kerbside \
  -derivedDataPath build -destination 'platform=macOS,arch=arm64' test
bash scripts/build.sh 0.1.0-preview.1
build/Build/Products/Release/Kerbside.app/Contents/MacOS/Kerbside --check-keychain
open build/Build/Products/Release/Kerbside.app
```

The keychain probe creates and deletes a disposable keychain; it does not change
the account password, login keychain, or FileVault. The test suite covers account
validation, LDIF parsing, filter escaping, and password-change state.

## Distribution

[GitHub Actions](https://github.com/sbekti/kerbside/actions) builds and tests the
app, runs the release-build keychain probe, and captures the first-run window.
Download the **Kerbside-arm64** artifact from a successful run. Unzip it, then
unzip the enclosed app archive and move `Kerbside.app` to Applications.

Builds are ad hoc signed and unnotarized. macOS may require first-open approval
in System Settings → Privacy & Security; updates may require Keychain approval.
Quit Kerbside before replacing it, and disable Launch at login before uninstalling.

Version tags create draft releases and Homebrew cask pull requests. See
[releasing](docs/RELEASING.md). For a published release:

```bash
brew install --cask sbekti/tap/kerbside
brew upgrade --cask kerbside
```

## License

[MIT](LICENSE), including [NoMAD attribution](THIRD_PARTY_NOTICES.md).
