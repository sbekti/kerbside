import Foundation
import Network
import OpenDirectory
import Security
import LocalAuthentication

enum CredentialStore {
    private static func query(_ account: Account) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "com.bekti.kerbside.ad",
         kSecAttrAccount as String: account.principal]
    }

    static func password(for account: Account) throws -> String? {
        var query = query(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        // Background refresh must never present repeated Keychain permission dialogs.
        let context = LAContext()
        context.interactionNotAllowed = true
        query[kSecUseAuthenticationContext as String] = context
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data, let password = String(data: data, encoding: .utf8) else {
            throw KerbsideError("Cannot read the saved AD credential. Sign in again to grant Keychain access (\(status)).")
        }
        return password
    }

    static func save(_ password: String, for account: Account) throws {
        let query = query(account)
        let update = [kSecValueData as String: Data(password.utf8)]
        var status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(query.merging(update) { _, new in new } as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw KerbsideError("Could not save the AD credential in Keychain (\(status)).") }
    }

    static func remove(_ account: Account) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KerbsideError("Could not remove the saved AD credential (\(status)).")
        }
    }
}

enum Directory {
    static func controller(for account: Account) throws -> String {
        let hosts = try SystemBridge.controllers(domain: account.domain)
        for host in hosts {
            // SRV data is not trusted as a URL or command fragment.
            guard (try? Account(domain: host, username: account.username)) != nil else { continue }
            let connection = NWConnection(host: NWEndpoint.Host(host), port: 636, using: .tcp)
            let ready = DispatchSemaphore(value: 0)
            connection.stateUpdateHandler = { state in
                if case .ready = state { ready.signal() }
                if case .failed = state { ready.signal() }
            }
            connection.start(queue: .global(qos: .utility))
            _ = ready.wait(timeout: .now() + 3)
            let connected: Bool
            if case .ready = connection.state { connected = true } else { connected = false }
            connection.cancel()
            if connected { return host }
        }
        throw KerbsideError("AD is unavailable. Connect to your AD network or VPN.")
    }

    static func user(_ account: Account, controller: String) throws -> DirectoryInfo {
        guard let cache = SystemBridge.cacheName(forPrincipal: account.principal) else {
            throw KerbsideError("Sign in to obtain a Kerberos ticket first.")
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ldapsearch")
        process.arguments = ["-LLL", "-N", "-Q", "-Y", "GSSAPI", "-H", "ldaps://\(controller):636",
                             "-b", account.baseDN, "-s", "sub", "-z", "2", "-l", "8",
                             "-o", "nettimeout=5", "-o", "ldif-wrap=no",
                             "(&(objectClass=user)(sAMAccountName=\(LDIF.escapeFilter(account.username))))",
                             "pwdLastSet", "msDS-UserPasswordExpiryTimeComputed", "userAccountControl"]
        var environment = ProcessInfo.processInfo.environment
        environment["KRB5CCNAME"] = cache
        environment["LDAPTLS_REQCERT"] = "demand"
        environment["LC_ALL"] = "C"
        process.environment = environment
        process.standardInput = FileHandle.nullDevice
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let timeout = DispatchWorkItem { if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 12, execute: timeout)
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        timeout.cancel()
        guard process.terminationStatus == 0 else {
            throw KerbsideError("The authenticated LDAPS lookup failed. Check the domain controller's TLS certificate and your AD connection.")
        }
        return try DirectoryInfo(ldif: String(decoding: data, as: UTF8.self))
    }
}

struct KeychainRepairNeeded: LocalizedError {
    let underlying: Error
    var errorDescription: String? {
        "Your Mac account password now matches AD, but the login keychain did not update. " +
        "Keep its previous password and choose Sync Password to repair it. " + underlying.localizedDescription
    }
}

enum LocalAccount {
    private static func record() throws -> ODRecord {
        let node = try ODNode(session: ODSession.default(), type: ODNodeType(kODNodeTypeLocalNodes))
        return try node.record(withRecordType: kODRecordTypeUsers, name: NSUserName(), attributes: nil)
    }

    static func preflight(newPassword: String, currentPassword: String) throws {
        try SystemBridge.checkLoginKeychain()
        let user = try record()
        try user.verifyPassword(currentPassword)
        try user.passwordChangeAllowed(newPassword)
    }

    static func sync(newPassword: String, currentPassword: String) throws {
        try SystemBridge.checkLoginKeychain()
        let user = try record()
        try user.verifyPassword(currentPassword)
        try user.passwordChangeAllowed(newPassword)
        if currentPassword != newPassword { try user.changePassword(currentPassword, toPassword: newPassword) }
        do {
            try SystemBridge.changeKeychain(path: nil, oldPassword: currentPassword, newPassword: newPassword)
        } catch { throw KeychainRepairNeeded(underlying: error) }
    }

    static func repairKeychain(currentMacPassword: String, previousKeychainPassword: String) throws {
        try record().verifyPassword(currentMacPassword)
        // Repair to the CURRENT local password. AD may have changed again since
        // the partial failure, so using the newest AD password here would be wrong.
        try SystemBridge.changeKeychain(path: nil, oldPassword: previousKeychainPassword, newPassword: currentMacPassword)
    }
}
