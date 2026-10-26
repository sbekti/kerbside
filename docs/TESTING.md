# macOS verification

Use a dedicated AD test identity and a temporary **local** Mac account. Do not
first test this on the only account that can unlock your everyday Mac. Keep the
test account's current and previous passwords available until all checks pass.
The app does not enable/disable FileVault or grant secure tokens.

## Disposable check

Run `Kerbside.app/Contents/MacOS/Kerbside --check-keychain`. A pass means only that
this build rejected an incorrect old password, changed a disposable file-based
keychain password with Unicode input, then locked and reopened the keychain.
The reopened keychain must reject the previous password, unlock with the new
password, and preserve the test item. Unexpected acceptance fails the probe.
If it fails, stop testing real-account password changes and report the output.

## Existing local account

1. Launch the app in the temporary Mac account. Check that Settings names the
   correct Mac account. Verify keyboard navigation, secure fields, light/dark
   appearance, and the menu. Enabling/disabling launch at login must agree with
   System Settings → General → Login Items.
2. Sign in to the AD test identity. No sync dialog should appear. Verify Kerberos
   tickets with `klist`; the Mac password must remain unchanged. Signing in again
   without an AD password change must not introduce a pending-sync warning.
   No new Mac or AD computer account should appear.
3. Add a harmless saved password to the login keychain using Keychain Access.
   Sync with a deliberately different AD password. Check that the item remains
   readable. Test screen lock/unlock, then log out and log in with the AD password.
   Read the saved item again after login; immediate access alone may use an
   already-unlocked keychain.
4. If this test account is FileVault-enabled, reboot and test disk unlock with
   the new password, followed by normal login and keychain access. Inspect secure
   token/volume-owner status using your normal Mac administration tools. Do not
   claim FileVault validation if the account cannot unlock the encrypted volume.
5. Change the AD password on another client. While connected, wait for the next
   check or wake/reconnect. Verify one notification, paused old-password attempts,
   and successful sign-in and sync using the new AD password.
6. Change the password through Kerbside. Check AD authentication, local login,
   login keychain, and FileVault again. Repeat with a non-ASCII password accepted
   by your policies. A rejected AD policy must leave the local account untouched.
7. Change the local password using System Settings. AD must remain unchanged.
   Explicit sync must request the current local password before aligning it with
   AD. For command-line changes, check keychain behavior separately.

## Failures and offline use

- Disconnect the AD network or VPN. Existing local login and FileVault unlock
  must keep working. Reconnect and verify checks resume without repeated prompts.
- Try an incorrect AD password once. Verify automatic attempts pause until a new
  explicit sign-in. A bad Mac password must not change the account or keychain.
- Cancel each dialog and verify the intended changes have not started. Once an
  AD change succeeds, a later failure must explicitly report that AD changed.
- If keychain update fails after a local update, verify the repair action requests
  the current Mac password and previous keychain password and preserves saved
  items. Sign out and disconnect the network before repair: it must still work
  without reading the saved AD credential. Change AD again before repair: repair
  must align the keychain with the current Mac password and leave pending AD sync
  intact. Never reset it.
- Confirm Repair Login Keychain is available even before configuring AD. Canceling
  it or entering an incorrect current Mac password must not change the keychain.
- Open Sync Password and leave the dialog open. Change AD elsewhere, then confirm
  Sync before the next background timestamp check. The saved old AD password must
  be rejected before any local password change is attempted.
- Restart the app with sync/repair pending. It must retain that state until a
  successful repair, not clear it merely because it saw the same AD timestamp.
- Switch the configured AD identity while repair is pending. The local repair
  warning must remain. Repair must clear only that warning, not pending AD sync.
- Leave a result alert open through a wake/network change. Background maintenance
  must wait until the alert is dismissed.
- Sign out. Verify the configured AD credential and principal's tickets are
  removed, other identities' tickets remain, and background sign-in stops.

Record the exact OS version, build SHA, and outcomes in the release review.
Compilation and the disposable probe alone are not a readiness claim.
