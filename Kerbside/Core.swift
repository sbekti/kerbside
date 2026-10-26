import Foundation

struct Account: Codable, Equatable {
    let domain: String
    let username: String

    init(domain: String, username: String) throws {
        let domain = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let username = username.trimmingCharacters(in: .whitespacesAndNewlines)
        let labels = domain.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, domain.utf8.count <= 253,
              labels.allSatisfy({ label in
                  !label.isEmpty && label.utf8.count <= 63 &&
                  label.first != "-" && label.last != "-" &&
                  label.unicodeScalars.allSatisfy { CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-").contains($0) }
              }) else { throw KerbsideError("Enter an AD DNS domain, such as ad.example.com.") }
        let parts = username.split(separator: "@", omittingEmptySubsequences: false)
        guard parts.count <= 2, let shortName = parts.first, !shortName.isEmpty,
              !shortName.contains(where: { $0.isWhitespace || $0 == "/" || $0 == "\\" || $0.isNewline }),
              !shortName.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              parts.count == 1 || parts[1].lowercased() == domain else {
            throw KerbsideError("Enter your AD username, or username@\(domain).")
        }
        self.domain = domain
        self.username = String(shortName)
    }

    var realm: String { domain.uppercased() }
    var principal: String { "\(username)@\(realm)" }
    var baseDN: String { domain.split(separator: ".").map { "DC=\($0)" }.joined(separator: ",") }
}

struct KerbsideError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

struct DirectoryInfo {
    let passwordChanged: String
    let passwordExpiry: Date?
    let neverExpires: Bool

    init(ldif: String) throws {
        let records = try LDIF.records(ldif)
        let users = records.filter { $0["pwdlastset"] != nil }
        guard users.count == 1, let changed = users[0]["pwdlastset"], UInt64(changed) != nil else {
            throw KerbsideError("AD did not return a unique user with a password-change timestamp.")
        }
        passwordChanged = changed
        let expiry = users[0]["msds-userpasswordexpirytimecomputed"].flatMap(UInt64.init)
        let flags = users[0]["useraccountcontrol"].flatMap(UInt64.init) ?? 0
        neverExpires = flags & 0x10000 != 0 || expiry == UInt64(Int64.max)
        passwordExpiry = neverExpires ? nil : expiry.flatMap(Self.fileTime)
    }

    private static func fileTime(_ value: UInt64) -> Date? {
        guard value > 0, value < UInt64(Int64.max) else { return nil }
        return Date(timeIntervalSince1970: Double(value) / 10_000_000 - 11_644_473_600)
    }
}

enum LDIF {
    // RFC 4515: escape filter values, not the surrounding filter expression.
    static func escapeFilter(_ value: String) -> String {
        value.utf8.map { byte in
            switch byte {
            case 0, 0x28, 0x29, 0x2a, 0x5c, 0x80...0xff:
                return String(format: "\\%02x", byte)
            default: return String(UnicodeScalar(byte))
            }
        }.joined()
    }

    static func records(_ text: String) throws -> [[String: String]] {
        var unfolded: [String] = []
        for line in text.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n") {
            if line.hasPrefix(" "), !unfolded.isEmpty {
                unfolded[unfolded.count - 1] += line.dropFirst()
            } else { unfolded.append(line) }
        }
        var records: [[String: String]] = []
        var current: [String: String] = [:]
        for line in unfolded + [""] {
            if line.isEmpty {
                if !current.isEmpty { records.append(current); current = [:] }
                continue
            }
            if line.hasPrefix("#") { continue }
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].lowercased()
            let rest = String(line[line.index(after: colon)...])
            let value: String
            if rest.hasPrefix(":") {
                guard let data = Data(base64Encoded: rest.dropFirst().trimmingCharacters(in: .whitespaces)),
                      let decoded = String(data: data, encoding: .utf8) else {
                    throw KerbsideError("AD returned invalid base64 data.")
                }
                value = decoded
            } else { value = rest.trimmingCharacters(in: .whitespaces) }
            if current[name] != nil { throw KerbsideError("AD returned a repeated attribute: \(name).") }
            current[name] = value
        }
        return records
    }
}

struct PasswordState: Codable, Equatable {
    var observed: String?
    var needsSync = false
    var needsKeychainRepair = false

    mutating func observe(_ timestamp: String) -> Bool {
        // A lagging RODC must not move the baseline backward and repeatedly
        // announce the same change. Zero is AD's explicit must-change state.
        if let observed, let previous = UInt64(observed), let latest = UInt64(timestamp),
           latest != 0, latest < previous { return false }
        let changed = observed != nil && observed != timestamp
        observed = timestamp
        if changed { needsSync = true }
        return changed
    }

    mutating func didSync() {
        needsSync = false
        needsKeychainRepair = false
    }
}
