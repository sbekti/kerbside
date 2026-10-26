import Foundation
import XCTest

final class CoreTests: XCTestCase {
    func testAccountNormalizesUPNWithoutRenamingTheMacAccount() throws {
        let account = try Account(domain: " AD.EXAMPLE.COM ", username: "alice@ad.example.com")
        XCTAssertEqual(account.principal, "alice@AD.EXAMPLE.COM")
        XCTAssertEqual(account.baseDN, "DC=ad,DC=example,DC=com")
        XCTAssertThrowsError(try Account(domain: "ad.example.com", username: "alice@another.example"))
        XCTAssertThrowsError(try Account(domain: "https://ad.example.com", username: "alice"))
        XCTAssertThrowsError(try Account(domain: "ad..example.com", username: "alice"))
        XCTAssertThrowsError(try Account(domain: "ad.example.com", username: "../alice"))
    }

    func testLDAPFilterCannotBeBroadenedByTheUsername() {
        XCTAssertEqual(LDIF.escapeFilter("a*)(uid=*)\\\0"), "a\\2a\\29\\28uid=\\2a\\29\\5c\\00")
        XCTAssertEqual(LDIF.escapeFilter("é"), "\\c3\\a9")
    }

    func testLDIFHandlesBase64FoldedLinesAndCaseInsensitiveAttributes() throws {
        let ldif = """
        # user result
        dn: CN=Alice,DC=example,DC=com
        PwdLastSet: 133485408000000000
        displayName:: QWxp
         Y2U=
        userAccountControl: 66048
        msDS-UserPasswordExpiryTimeComputed: 9223372036854775807
        """
        let records = try LDIF.records(ldif)
        XCTAssertEqual(records[0]["displayname"], "Alice")
        let info = try DirectoryInfo(ldif: ldif)
        XCTAssertTrue(info.neverExpires)
        XCTAssertNil(info.passwordExpiry)
    }

    func testDirectoryRejectsMissingOrAmbiguousPasswordState() {
        XCTAssertThrowsError(try DirectoryInfo(ldif: "dn: CN=Alice\n"))
        XCTAssertThrowsError(try DirectoryInfo(ldif: "pwdLastSet: 123\n\npwdLastSet: 456\n"))
        XCTAssertThrowsError(try DirectoryInfo(ldif: "pwdLastSet: invalid\n"))
        XCTAssertThrowsError(try DirectoryInfo(ldif: "pwdLastSet: 123\npwdLastSet: 456\n"))
        XCTAssertThrowsError(try LDIF.records("pwdLastSet:: !not-base64!\n"))
    }

    func testDirectoryDistinguishesMustChangeFromNeverExpires() throws {
        let never = try DirectoryInfo(ldif: "pwdLastSet: 123\nuserAccountControl: 66048\n")
        XCTAssertTrue(never.neverExpires)
        let mustChange = try DirectoryInfo(ldif: "pwdLastSet: 0\nmsDS-UserPasswordExpiryTimeComputed: 0\n")
        XCTAssertFalse(mustChange.neverExpires)
        XCTAssertNil(mustChange.passwordExpiry)
        let date = try DirectoryInfo(ldif: "pwdLastSet: 123\nmsDS-UserPasswordExpiryTimeComputed: 116444736100000000\n")
        XCTAssertEqual(date.passwordExpiry?.timeIntervalSince1970, 10)
    }

    func testObservedChangeRemainsPendingAcrossRestartAndRepeatedChecks() throws {
        var state = PasswordState()
        XCTAssertFalse(state.observe("100"))
        XCTAssertFalse(state.needsSync)
        XCTAssertTrue(state.observe("200"))
        state = try JSONDecoder().decode(PasswordState.self, from: JSONEncoder().encode(state))
        XCTAssertFalse(state.observe("200"))
        XCTAssertTrue(state.needsSync)
        state.didSync()
        XCTAssertFalse(state.needsSync)
    }

    func testLaggingControllerDoesNotRepeatAChangeButMustChangeIsDetected() {
        var state = PasswordState()
        XCTAssertFalse(state.observe("100"))
        XCTAssertTrue(state.observe("200"))
        state.didSync()
        XCTAssertFalse(state.observe("100"))
        XCTAssertEqual(state.observed, "200")
        XCTAssertFalse(state.needsSync)
        XCTAssertTrue(state.observe("0"))
        XCTAssertTrue(state.needsSync)
    }

    func testRepairMigrationSurvivesADAccountChangesAndSignOut() throws {
        let suite = "kerbside-tests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(Data(#"{"observed":"100","needsSync":true,"needsKeychainRepair":true}"#.utf8), forKey: "passwordState")
        KeychainRepairState.migrate(in: defaults)
        XCTAssertTrue(defaults.bool(forKey: KeychainRepairState.key))

        // Switching AD identities replaces directory state, not local repair state.
        defaults.set(try JSONEncoder().encode(PasswordState()), forKey: "passwordState")
        defaults.set(true, forKey: "signedOut")
        let reopened = try XCTUnwrap(UserDefaults(suiteName: suite))
        KeychainRepairState.migrate(in: reopened)
        XCTAssertTrue(reopened.bool(forKey: KeychainRepairState.key))
    }

    func testRepairDoesNotClearPendingADSyncOrReimportTheLegacyFlag() throws {
        let suite = "kerbside-tests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(Data(#"{"observed":"100","needsSync":true,"needsKeychainRepair":true}"#.utf8), forKey: "passwordState")
        KeychainRepairState.migrate(in: defaults)
        defaults.set(false, forKey: KeychainRepairState.key)
        KeychainRepairState.migrate(in: defaults)
        XCTAssertFalse(defaults.bool(forKey: KeychainRepairState.key))
        let state = try JSONDecoder().decode(PasswordState.self, from: XCTUnwrap(defaults.data(forKey: "passwordState")))
        XCTAssertTrue(state.needsSync)
        XCTAssertEqual(state.observed, "100")
    }

    func testFreshPreferencesDoNotRequireRepair() throws {
        let suite = "kerbside-tests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        KeychainRepairState.migrate(in: defaults)
        XCTAssertEqual(defaults.object(forKey: KeychainRepairState.key) as? Bool, false)
    }

    func testPasswordUpdateAuthorizesAfterPreflightAndBeforeWrites() throws {
        var steps: [String] = []
        try PasswordUpdate.run(preflight: { steps.append("preflight") },
                               authorize: { steps.append("authorize") },
                               updateAccount: { steps.append("account") },
                               updateKeychain: { steps.append("keychain") })
        XCTAssertEqual(steps, ["preflight", "authorize", "account", "keychain"])
    }

    func testRejectedPreflightOrAuthorizationPreventsAllPasswordWrites() {
        for failedStep in ["preflight", "authorize"] {
            var writes = 0
            let failure = KerbsideError("Rejected \(failedStep)")
            XCTAssertThrowsError(try PasswordUpdate.run(preflight: {
                if failedStep == "preflight" { throw failure }
            }, authorize: {
                if failedStep == "authorize" { throw failure }
            }, updateAccount: { writes += 1 }, updateKeychain: { writes += 1 })) { error in
                XCTAssertFalse(error is PasswordUpdateFailure)
                XCTAssertEqual(error.localizedDescription, failure.localizedDescription)
            }
            XCTAssertEqual(writes, 0)
        }
    }

    func testAccountFailureDoesNotAttemptKeychainUpdate() {
        var keychainWrites = 0
        XCTAssertThrowsError(try PasswordUpdate.run(preflight: {}, authorize: {}, updateAccount: {
            throw KerbsideError("Account error")
        }, updateKeychain: { keychainWrites += 1 })) { error in
            guard case PasswordUpdateFailure.account = error else { return XCTFail("Expected account-stage failure") }
            XCTAssertTrue(error.localizedDescription.contains("could not be confirmed"))
            XCTAssertTrue(error.localizedDescription.contains("keychain update was not attempted"))
        }
        XCTAssertEqual(keychainWrites, 0)
    }

    func testKeychainFailureReportsCompletedAccountUpdate() {
        var accountUpdated = false
        XCTAssertThrowsError(try PasswordUpdate.run(preflight: {}, authorize: {}, updateAccount: {
            accountUpdated = true
        }, updateKeychain: { throw KerbsideError("Keychain error") })) { error in
            guard case PasswordUpdateFailure.keychain = error else { return XCTFail("Expected keychain-stage failure") }
            XCTAssertTrue(error.localizedDescription.contains("Mac account password matches"))
            XCTAssertTrue(error.localizedDescription.contains("keychain update could not be confirmed"))
        }
        XCTAssertTrue(accountUpdated)
    }
}
