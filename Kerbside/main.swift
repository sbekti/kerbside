import AppKit

if CommandLine.arguments.contains("--check-keychain") {
    do {
        try SystemBridge.probeKeychain()
        print("PASS: disposable keychain rejected incorrect and previous passwords, unlocked with its new Unicode password after reopening, and preserved an item.")
        print("This does not validate the login keychain, local-account password, or FileVault. See docs/TESTING.md.")
        exit(0)
    } catch {
        fputs("FAIL: \(error.localizedDescription)\n", stderr)
        exit(1)
    }
}

let app = NSApplication.shared
let controller = AppController()
app.delegate = controller
app.setActivationPolicy(.accessory)
app.run()
