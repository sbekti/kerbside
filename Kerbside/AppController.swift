import AppKit
import ServiceManagement
import SystemConfiguration
import UserNotifications

private struct SignInNeeded: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

private struct RemotePasswordChanged: LocalizedError {
    let cause: Error
    var errorDescription: String? {
        "Your AD password changed. Use the new AD password from now on. " +
        "The remaining update did not complete: " + cause.localizedDescription
    }
}

final class AppController: NSObject, NSApplicationDelegate {
    private let defaults = UserDefaults.standard
    private let queue = DispatchQueue(label: "com.bekti.kerbside.work", qos: .utility)
    private var item: NSStatusItem!
    private var timer: Timer?
    private var networkStore: SCDynamicStore?
    private var account: Account?
    private var passwordState = PasswordState()
    private var busy = false
    private var presentingDialog = false
    private var signedOut = true
    private var authPaused = false
    private var status = "Not configured"
    private var ticketExpiry: Date?
    private var directoryInfo: DirectoryInfo?

    func applicationDidFinishLaunching(_ notification: Notification) {
        if let data = defaults.data(forKey: "account"), let saved = try? JSONDecoder().decode(Account.self, from: data) {
            account = try? Account(domain: saved.domain, username: saved.username)
        }
        if let data = defaults.data(forKey: "passwordState"), let saved = try? JSONDecoder().decode(PasswordState.self, from: data) {
            passwordState = saved
        }
        signedOut = defaults.object(forKey: "signedOut") as? Bool ?? true
        authPaused = defaults.bool(forKey: "authPaused")
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.image = NSImage(systemSymbolName: "key.horizontal", accessibilityDescription: "Kerbside")
        refreshMenu()
        timer = Timer.scheduledTimer(withTimeInterval: 15 * 60, repeats: true) { [weak self] _ in self?.maintain() }
        timer?.tolerance = 90
        NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(woke), name: NSWorkspace.didWakeNotification, object: nil)
        watchNetwork()
        if account == nil { DispatchQueue.main.async { self.settings() } }
        else { maintain() }
    }

    private func persist() {
        defaults.set(try? JSONEncoder().encode(passwordState), forKey: "passwordState")
        defaults.set(signedOut, forKey: "signedOut")
        defaults.set(authPaused, forKey: "authPaused")
    }

    private func watchNetwork() {
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)
        networkStore = SCDynamicStoreCreate(nil, "com.bekti.kerbside" as CFString, { _, _, raw in
            guard let raw else { return }
            let controller = Unmanaged<AppController>.fromOpaque(raw).takeUnretainedValue()
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { controller.maintain() }
        }, &context)
        if let networkStore {
            let patterns = ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6", "State:/Network/Service/.*/DNS"] as CFArray
            SCDynamicStoreSetNotificationKeys(networkStore, nil, patterns)
            if let source = SCDynamicStoreCreateRunLoopSource(nil, networkStore, 0) {
                CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes)
            }
        }
    }

    @objc private func woke() { maintain() }

    private func refreshMenu() {
        guard item != nil else { return }
        let menu = NSMenu()
        menu.autoenablesItems = false
        func add(_ title: String, _ action: Selector? = nil, enabled: Bool = true) {
            let entry = NSMenuItem(title: title, action: action, keyEquivalent: "")
            entry.target = self
            entry.isEnabled = action != nil && enabled && !busy
            menu.addItem(entry)
        }
        add(account?.principal ?? "Kerbside")
        let displayStatus = busy ? "Working…" : signedOut && account != nil ? "Signed out" : status
        add(displayStatus)
        if let expiry = ticketExpiry, expiry > Date() {
            add("Ticket expires \(DateFormatter.localizedString(from: expiry, dateStyle: .none, timeStyle: .short))")
        }
        if let info = directoryInfo {
            if info.neverExpires { add("Password does not expire") }
            else if let expiry = info.passwordExpiry {
                add("Password expires \(DateFormatter.localizedString(from: expiry, dateStyle: .medium, timeStyle: .none))")
            }
        }
        if passwordState.needsKeychainRepair { add("Login keychain needs repair") }
        else if passwordState.needsSync { add("Password sync needed") }
        menu.addItem(.separator())
        let validTicket = ticketExpiry.map { $0 > Date() } ?? false
        add(validTicket && !authPaused ? "Renew Tickets" : "Sign In…", #selector(signInOrRenew), enabled: account != nil)
        add(passwordState.needsKeychainRepair ? "Repair Login Keychain…" : "Sync Password…", #selector(syncPassword), enabled: account != nil && !signedOut)
        add("Change Password…", #selector(changePassword), enabled: account != nil && !passwordState.needsKeychainRepair)
        add("Sign Out", #selector(signOut), enabled: account != nil && !signedOut)
        menu.addItem(.separator())
        add("Settings…", #selector(settings))
        add("About Kerbside", #selector(about))
        let quit = NSMenuItem(title: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        quit.target = NSApp
        quit.isEnabled = !busy
        menu.addItem(quit)
        item.menu = menu
        item.button?.appearsDisabled = signedOut
        item.button?.toolTip = "Kerbside: \(displayStatus)"
    }

    // One serial work queue keeps authentication, directory reads, and changes from overlapping.
    private func run<Value>(_ work: @escaping () throws -> Value, completion: @escaping (Result<Value, Error>) -> Void) {
        guard !busy else { return }
        busy = true
        refreshMenu()
        queue.async {
            let result = Result { try work() }
            DispatchQueue.main.async {
                self.busy = false
                completion(result)
                self.persist()
                self.refreshMenu()
            }
        }
    }

    private func observe(_ info: DirectoryInfo) {
        directoryInfo = info
        if passwordState.observe(info.passwordChanged) {
            authPaused = true
            notify("AD password changed", "Sign in with your new AD password to sync this Mac.")
        }
    }

    private func maintain() {
        guard let account, !signedOut, !busy, !presentingDialog else { return }
        let paused = authPaused
        let observed = passwordState.observed
        run({ () -> (DirectoryInfo, Date?) in
            let controller = try Directory.controller(for: account)
            var expiry = SystemBridge.ticketExpiry(forPrincipal: account.principal)
            if expiry == nil || expiry! <= Date() {
                guard !paused, let password = try CredentialStore.password(for: account) else {
                    throw SignInNeeded(message: "Sign in to obtain an AD ticket.")
                }
                do { try SystemBridge.authenticate(principal: account.principal, password: password) }
                catch { throw SignInNeeded(message: error.localizedDescription) }
                expiry = SystemBridge.ticketExpiry(forPrincipal: account.principal)
            }
            let info = try Directory.user(account, controller: controller)
            // Read the timestamp before using the saved password, so a known change
            // cannot lead to an automatic attempt with the previous password.
            if !paused && (observed == nil || observed == info.passwordChanged),
               let expiry, expiry.timeIntervalSinceNow < 30 * 60,
               let password = try CredentialStore.password(for: account) {
                do { try SystemBridge.authenticate(principal: account.principal, password: password) }
                catch { throw SignInNeeded(message: error.localizedDescription) }
            }
            return (info, SystemBridge.ticketExpiry(forPrincipal: account.principal))
        }, completion: { result in
            switch result {
            case .success(let (info, expiry)):
                self.observe(info)
                self.ticketExpiry = expiry
                self.status = self.authPaused ? "Sign in needed" : "Connected"
            case .failure(let error):
                if error is SignInNeeded {
                    if !self.authPaused { self.notify("Sign in needed", "Kerbside has paused automatic authentication. Sign in to continue.") }
                    self.authPaused = true
                    self.status = "Sign in needed"
                } else { self.status = "AD unavailable or check failed" }
            }
        })
    }

    @objc private func signInOrRenew() {
        if !signedOut && !authPaused, let ticketExpiry, ticketExpiry > Date() {
            guard let account else { return }
            run({ () -> DirectoryInfo in
                let controller = try Directory.controller(for: account)
                guard let password = try CredentialStore.password(for: account) else { throw SignInNeeded(message: "Sign in again.") }
                try SystemBridge.authenticate(principal: account.principal, password: password)
                return try Directory.user(account, controller: controller)
            }, completion: { result in
                switch result {
                case .success(let info):
                    self.observe(info)
                    self.ticketExpiry = SystemBridge.ticketExpiry(forPrincipal: account.principal)
                    self.status = "Connected"
                case .failure(let error):
                    self.authPaused = true
                    self.alert("Could not renew tickets", error.localizedDescription)
                }
            })
        } else { signIn() }
    }

    private func signIn() {
        guard let account, let values = form("Sign In", message: account.principal,
            fields: [("AD password", true, "")], button: "Sign In") else { return }
        let password = values[0]
        guard !password.isEmpty else { return }
        run({ () -> DirectoryInfo in
            let controller = try Directory.controller(for: account)
            try SystemBridge.authenticate(principal: account.principal, password: password)
            try CredentialStore.save(password, for: account)
            return try Directory.user(account, controller: controller)
        }, completion: { result in
            switch result {
            case .success(let info):
                self.signedOut = false
                self.directoryInfo = info
                _ = self.passwordState.observe(info.passwordChanged)
                self.authPaused = false
                self.passwordState.needsSync = true
                self.ticketExpiry = SystemBridge.ticketExpiry(forPrincipal: account.principal)
                self.status = "Connected"
                self.persist()
                self.requestNotifications()
                self.offerSync(password: password)
            case .failure(let error):
                self.authPaused = true
                self.status = "Sign in incomplete"
                self.alert("Could not finish sign-in", error.localizedDescription)
            }
        })
    }

    @objc private func syncPassword() {
        guard let account else { return }
        do {
            guard !authPaused, let password = try CredentialStore.password(for: account) else { signIn(); return }
            // A saved credential alone is not proof that it is still AD's current
            // password. Reauthenticate before offering a local password change.
            run({
                _ = try Directory.controller(for: account)
                try SystemBridge.authenticate(principal: account.principal, password: password)
            }, completion: { result in
                switch result {
                case .success: self.offerSync(password: password)
                case .failure(let error):
                    self.authPaused = true
                    self.alert("Could not verify the AD password", error.localizedDescription + " Sign in again before syncing.")
                }
            })
        } catch { alert("Sign in needed", error.localizedDescription); signIn() }
    }

    private func offerSync(password: String) {
        if passwordState.needsKeychainRepair {
            guard let values = form("Repair Login Keychain", message:
                "Update the login keychain to match your current Mac password while preserving its saved items.",
                fields: [("Current Mac password", true, ""), ("Previous login keychain password", true, "")], button: "Repair") else { return }
            run({ try LocalAccount.repairKeychain(currentMacPassword: values[0], previousKeychainPassword: values[1]) }, completion: { result in
                switch result {
                case .success:
                    self.passwordState.needsKeychainRepair = false
                    if values[0] == password {
                        self.passwordState.didSync()
                        self.alert("Keychain repaired", "Your Mac password and login keychain match the verified AD password.")
                    } else {
                        self.passwordState.needsSync = true
                        self.alert("Keychain repaired", "The login keychain now matches your Mac password. Choose Sync Password to align both with the current AD password.")
                    }
                case .failure(let error): self.alert("Keychain repair incomplete", error.localizedDescription)
                }
            })
            return
        }
        guard let values = form("Sync Mac Password", message:
            "Update the local account \(NSUserName()) and login keychain to match your AD password. Saved keychain items will be preserved.",
            fields: [("Current Mac password", true, "")], button: "Sync") else { return }
        run({ try LocalAccount.sync(newPassword: password, currentPassword: values[0]) }, completion: { result in
            switch result {
            case .success:
                self.passwordState.didSync()
                self.alert("Password sync complete", "Your Mac account and login keychain now match AD. Verify FileVault at the next reboot before relying on the new password.")
            case .failure(let error):
                self.passwordState.needsSync = true
                if error is KeychainRepairNeeded { self.passwordState.needsKeychainRepair = true }
                self.alert("Password sync incomplete", error.localizedDescription)
            }
        })
    }

    @objc private func changePassword() {
        guard let account, let values = form("Change AD Password", message:
            "Change your own AD password, then sync the local account \(NSUserName()) and login keychain. AD and macOS are separate updates; a partial failure cannot be rolled back automatically.",
            fields: [("Current AD password", true, ""), ("New AD password", true, ""),
                     ("Confirm new password", true, ""), ("Current Mac password", true, "")], button: "Change Password") else { return }
        guard !values[1].isEmpty, values[1] == values[2] else { alert("Passwords do not match", "Enter the same nonempty new password twice."); return }
        run({ () -> DirectoryInfo? in
            let controller = try Directory.controller(for: account)
            try LocalAccount.preflight(newPassword: values[1], currentPassword: values[3])
            try SystemBridge.changePassword(principal: account.principal, oldPassword: values[0], newPassword: values[1])
            do {
                try CredentialStore.save(values[1], for: account)
                try LocalAccount.sync(newPassword: values[1], currentPassword: values[3])
            } catch { throw RemotePasswordChanged(cause: error) }
            // A completed password change must not be reported as failed merely
            // because replication or a subsequent ticket refresh is delayed.
            try? SystemBridge.authenticate(principal: account.principal, password: values[1])
            return try? Directory.user(account, controller: controller)
        }, completion: { result in
            switch result {
            case .success(let info):
                if let info {
                    self.directoryInfo = info
                    _ = self.passwordState.observe(info.passwordChanged)
                }
                self.passwordState.didSync()
                self.authPaused = false
                self.signedOut = false
                self.ticketExpiry = SystemBridge.ticketExpiry(forPrincipal: account.principal)
                self.status = "Password changed"
                self.alert("Password changed", "AD, your local account, and the login keychain were updated. Use the new password. Verify FileVault at the next reboot.")
            case .failure(let error):
                if let partial = error as? RemotePasswordChanged {
                    self.passwordState.needsSync = true
                    self.passwordState.needsKeychainRepair = partial.cause is KeychainRepairNeeded
                    self.signedOut = false
                    self.authPaused = true
                }
                self.alert("Password change incomplete", error.localizedDescription)
            }
        })
    }

    @objc private func signOut() {
        guard let account else { return }
        run({
            try CredentialStore.remove(account)
            try SystemBridge.signOut(principal: account.principal)
        }, completion: { result in
            switch result {
            case .success:
                self.signedOut = true
                self.authPaused = false
                self.ticketExpiry = nil
                self.directoryInfo = nil
                self.status = "Signed out"
            case .failure(let error): self.alert("Sign-out incomplete", error.localizedDescription)
            }
        })
    }

    @objc private func settings() {
        let launch = NSButton(checkboxWithTitle: "Launch at login", target: nil, action: nil)
        let launchStatus = SMAppService.mainApp.status
        launch.state = launchStatus == .enabled || launchStatus == .requiresApproval ? .on : .off
        guard let values = form("Kerbside Settings", message:
            "Link your AD account to the local Mac account \(NSUserName()). Your AD password is saved in your login Keychain.",
            fields: [("AD domain", false, account?.domain ?? ""), ("AD username", false, account?.username ?? NSUserName())],
            button: "Save", checkbox: launch) else { return }
        do {
            let newAccount = try Account(domain: values[0], username: values[1])
            if let old = account, old != newAccount {
                guard confirm("Switch AD account?", "Remove the saved credential and tickets for \(old.principal)? Your local Mac account will stay the same.") else { return }
                try CredentialStore.remove(old)
                try SystemBridge.signOut(principal: old.principal)
            }
            let changed = newAccount != account
            account = newAccount
            defaults.set(try JSONEncoder().encode(newAccount), forKey: "account")
            if changed {
                passwordState = PasswordState()
                signedOut = true
                authPaused = false
                directoryInfo = nil
                ticketExpiry = nil
                persist()
            }
            if launch.state == .on && SMAppService.mainApp.status != .enabled && SMAppService.mainApp.status != .requiresApproval { try SMAppService.mainApp.register() }
            else if launch.state == .off && SMAppService.mainApp.status != .notRegistered { try SMAppService.mainApp.unregister() }
            if launch.state == .on && SMAppService.mainApp.status == .requiresApproval {
                alert("Approve launch at login", "Enable Kerbside in System Settings → General → Login Items.")
                SMAppService.openSystemSettingsLoginItems()
            }
            refreshMenu()
            if changed { signIn() }
        } catch { alert("Could not finish settings", error.localizedDescription) }
    }

    @objc private func about() {
        NSApp.activate(ignoringOtherApps: true)
        NSApp.orderFrontStandardAboutPanel(options: [.credits: NSAttributedString(string:
            "A small AD companion, adapted from NoMAD. MIT licensed.\nExperimental: validate password sync and FileVault on a test account before daily use.\nhttps://github.com/sbekti/kerbside")])
    }

    private func requestNotifications() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { _, _ in }
    }

    private func notify(_ title: String, _ body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "ad-sign-in", content: content, trigger: nil))
    }

    private func alert(_ title: String, _ message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }

    private func confirm(_ title: String, _ message: String) -> Bool {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "Switch Account")
        alert.addButton(withTitle: "Cancel")
        NSApp.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertFirstButtonReturn
    }

    private func form(_ title: String, message: String, fields: [(String, Bool, String)], button: String,
                      checkbox: NSButton? = nil) -> [String]? {
        guard !busy, !presentingDialog else { return nil }
        presentingDialog = true
        defer { presentingDialog = false }
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: button)
        alert.addButton(withTitle: "Cancel")
        let extra: CGFloat = checkbox == nil ? 0 : 28
        let view = NSView(frame: NSRect(x: 0, y: 0, width: 370, height: CGFloat(fields.count * 54) + extra))
        var inputs: [NSTextField] = []
        for (index, field) in fields.enumerated() {
            let y = view.frame.height - CGFloat((index + 1) * 54)
            let label = NSTextField(labelWithString: field.0)
            label.frame = NSRect(x: 0, y: y + 29, width: 370, height: 18)
            let input = field.1 ? NSSecureTextField() : NSTextField()
            input.frame = NSRect(x: 0, y: y + 3, width: 370, height: 24)
            input.stringValue = field.2
            input.isEditable = true
            input.isSelectable = true
            input.setAccessibilityLabel(field.0)
            view.addSubview(label)
            view.addSubview(input)
            inputs.append(input)
        }
        if let checkbox { checkbox.frame = NSRect(x: 0, y: 0, width: 370, height: 24); view.addSubview(checkbox) }
        for (index, input) in inputs.enumerated() { input.nextKeyView = index + 1 < inputs.count ? inputs[index + 1] : alert.buttons.first }
        alert.accessoryView = view
        alert.window.initialFirstResponder = inputs.first
        NSApp.activate(ignoringOtherApps: true)
        defer { for input in inputs { input.stringValue = "" } }
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        return inputs.map(\.stringValue)
    }
}
