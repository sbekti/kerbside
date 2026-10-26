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
        state.needsKeychainRepair = true
        XCTAssertFalse(state.observe("200"))
        XCTAssertTrue(state.needsKeychainRepair)
        state.didSync()
        XCTAssertFalse(state.needsSync)
        XCTAssertFalse(state.needsKeychainRepair)
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
}
