// Kerberos authentication and legacy keychain calls adapted from NoMAD.
// Copyright (c) 2016 Joel Rennich. MIT; see THIRD_PARTY_NOTICES.md.
#import "SystemBridge.h"
#import <GSS/GSS.h>
#import <Security/Security.h>
#import <krb5/krb5.h>
#import <dlfcn.h>
#import <dns_sd.h>
#import <sys/select.h>

static BOOL fail(NSError **error, NSString *message, NSInteger code) {
    if (error) *error = [NSError errorWithDomain:@"com.bekti.kerbside" code:code
                                      userInfo:@{NSLocalizedDescriptionKey: message}];
    return NO;
}

static krb5_ccache findCache(krb5_context context, NSString *principal) {
    krb5_cccol_cursor cursor = NULL;
    krb5_ccache cache = NULL, found = NULL;
    if (krb5_cccol_cursor_new(context, &cursor) == 0) {
        while (krb5_cccol_cursor_next(context, cursor, &cache) == 0 && cache != NULL) {
            krb5_principal actual = NULL;
            if (krb5_cc_get_principal(context, cache, &actual) == 0) {
                char *canonical = NULL;
                BOOL match = NO;
                if (krb5_unparse_name(context, actual, &canonical) == 0) {
                    match = [[NSString stringWithUTF8String:canonical] caseInsensitiveCompare:principal] == NSOrderedSame;
                    krb5_free_unparsed_name(context, canonical);
                }
                krb5_free_principal(context, actual);
                if (match) { found = cache; break; }
            }
            krb5_cc_close(context, cache);
        }
        krb5_cccol_cursor_free(context, &cursor);
    }
    return found;
}

static void srvReply(DNSServiceRef service, DNSServiceFlags flags, uint32_t index,
                     DNSServiceErrorType error, const char *name, uint16_t type,
                     uint16_t dnsClass, uint16_t length, const void *data, uint32_t ttl, void *raw) {
    NSMutableDictionary *context = (__bridge NSMutableDictionary *)raw;
    if (error) { context[@"error"] = @(error); context[@"done"] = @YES; return; }
    if (length > 7 && (flags & kDNSServiceFlagsAdd)) {
        const unsigned char *bytes = data;
        NSUInteger offset = 6;
        NSMutableArray *labels = [NSMutableArray array];
        while (offset < length && bytes[offset] > 0) {
            NSUInteger count = bytes[offset++];
            if (count > 63 || offset + count > length) { [labels removeAllObjects]; break; }
            NSString *label = [[NSString alloc] initWithBytes:bytes + offset length:count encoding:NSASCIIStringEncoding];
            if (!label) { [labels removeAllObjects]; break; }
            [labels addObject:label];
            offset += count;
        }
        if (labels.count && offset < length && bytes[offset] == 0) {
            [context[@"records"] addObject:@{ @"host": [[labels componentsJoinedByString:@"."] lowercaseString],
                @"priority": @((bytes[0] << 8) | bytes[1]) }];
        }
    }
    context[@"done"] = @(!(flags & kDNSServiceFlagsMoreComing));
}

@implementation SystemBridge
+ (NSArray<NSString *> *)controllersForDomain:(NSString *)domain error:(NSError **)error {
    // DNSServiceQueryRecord honors macOS scoped DNS (including VPN split DNS).
    // dig/res_query would bypass those resolver selections.
    NSMutableDictionary *context = [@{ @"records": [NSMutableArray array], @"done": @NO, @"error": @0 } mutableCopy];
    DNSServiceRef service = NULL;
    NSString *query = [@"_ldap._tcp." stringByAppendingString:domain];
    DNSServiceErrorType status = DNSServiceQueryRecord(&service, 0, kDNSServiceInterfaceIndexAny,
        query.UTF8String, kDNSServiceType_SRV, kDNSServiceClass_IN, srvReply, (__bridge void *)context);
    if (status) { fail(error, @"Could not start AD DNS discovery.", status); return nil; }
    int descriptor = DNSServiceRefSockFD(service);
    if (descriptor < 0 || descriptor >= FD_SETSIZE) {
        DNSServiceRefDeallocate(service);
        fail(error, @"Could not open the DNS discovery connection.", 8);
        return nil;
    }
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:5];
    while (![context[@"done"] boolValue] && deadline.timeIntervalSinceNow > 0) {
        fd_set descriptors; FD_ZERO(&descriptors); FD_SET(descriptor, &descriptors);
        struct timeval timeout = { 1, 0 };
        int ready = select(descriptor + 1, &descriptors, NULL, NULL, &timeout);
        if (ready < 0) break;
        if (ready > 0 && DNSServiceProcessResult(service) != kDNSServiceErr_NoError) break;
    }
    DNSServiceRefDeallocate(service);
    NSArray *records = [context[@"records"] sortedArrayUsingDescriptors:@[[NSSortDescriptor sortDescriptorWithKey:@"priority" ascending:YES]]];
    if (!records.count) { fail(error, @"AD DNS records are unavailable. Connect to your AD network or VPN, then try again.", 7); return nil; }
    NSMutableOrderedSet *hosts = [NSMutableOrderedSet orderedSet];
    for (NSDictionary *record in records) [hosts addObject:record[@"host"]];
    return hosts.array;
}
+ (BOOL)authenticatePrincipal:(NSString *)principal password:(NSString *)password error:(NSError **)error {
    gss_name_t name = GSSCreateName((__bridge CFStringRef)principal, GSS_C_NT_USER_NAME, NULL);
    if (!name) return fail(error, @"Could not create the Kerberos identity.", 1);
    gss_cred_id_t credential = GSS_C_NO_CREDENTIAL;
    CFErrorRef detail = NULL;
    OM_uint32 result = gss_aapl_initial_cred(name, GSS_KRB5_MECHANISM,
        (__bridge CFDictionaryRef)@{(__bridge NSString *)kGSSICPassword: password}, &credential, &detail);
    CFRelease(name);
    if (credential != GSS_C_NO_CREDENTIAL) { OM_uint32 minor; gss_release_cred(&minor, &credential); }
    if (result != GSS_S_COMPLETE) {
        if (detail) { if (error) *error = CFBridgingRelease(detail); else CFRelease(detail); }
        else fail(error, @"AD authentication failed. Check your password and connectivity.", 2);
        return NO;
    }
    if (detail) CFRelease(detail);
    return YES;
}

+ (BOOL)changePasswordForPrincipal:(NSString *)principal oldPassword:(NSString *)oldPassword
                      newPassword:(NSString *)newPassword error:(NSError **)error {
    gss_name_t name = GSSCreateName((__bridge CFStringRef)principal, GSS_C_NT_USER_NAME, NULL);
    if (!name) return fail(error, @"Could not create the Kerberos identity.", 1);
    CFErrorRef detail = NULL;
    OM_uint32 result = gss_aapl_change_password(name, GSS_KRB5_MECHANISM,
        (__bridge CFDictionaryRef)@{(__bridge NSString *)kGSSChangePasswordOldPassword: oldPassword,
                                   (__bridge NSString *)kGSSChangePasswordNewPassword: newPassword}, &detail);
    CFRelease(name);
    if (result != GSS_S_COMPLETE) {
        if (detail) { if (error) *error = CFBridgingRelease(detail); else CFRelease(detail); }
        else fail(error, @"AD rejected the password change.", 3);
        return NO;
    }
    if (detail) CFRelease(detail);
    return YES;
}

+ (NSString *)cacheNameForPrincipal:(NSString *)principal {
    krb5_context context = NULL;
    if (krb5_init_context(&context)) return nil;
    krb5_ccache cache = findCache(context, principal);
    NSString *name = nil;
    if (cache) {
        name = [NSString stringWithFormat:@"%s:%s", krb5_cc_get_type(context, cache), krb5_cc_get_name(context, cache)];
        krb5_cc_close(context, cache);
    }
    krb5_free_context(context);
    return name;
}

+ (NSDate *)ticketExpiryForPrincipal:(NSString *)principal {
    krb5_context context = NULL;
    if (krb5_init_context(&context)) return nil;
    krb5_ccache cache = findCache(context, principal);
    krb5_creds match = {0}, ticket = {0};
    NSDate *date = nil;
    NSString *realm = [[principal componentsSeparatedByString:@"@"] lastObject];
    NSString *server = [NSString stringWithFormat:@"krbtgt/%@@%@", realm, realm];
    if (cache && krb5_cc_get_principal(context, cache, &match.client) == 0 &&
        krb5_parse_name(context, server.UTF8String, &match.server) == 0 &&
        krb5_cc_retrieve_cred(context, cache, 0, &match, &ticket) == 0) {
        date = [NSDate dateWithTimeIntervalSince1970:ticket.times.endtime];
        krb5_free_cred_contents(context, &ticket);
    }
    if (match.client) krb5_free_principal(context, match.client);
    if (match.server) krb5_free_principal(context, match.server);
    if (cache) krb5_cc_close(context, cache);
    krb5_free_context(context);
    return date;
}

+ (BOOL)signOutPrincipal:(NSString *)principal error:(NSError **)error {
    krb5_context context = NULL;
    if (krb5_init_context(&context)) return fail(error, @"Could not open the Kerberos cache.", 4);
    krb5_ccache cache = findCache(context, principal);
    krb5_error_code result = cache ? krb5_cc_destroy(context, cache) : 0;
    krb5_free_context(context);
    return result == 0 || fail(error, @"Could not remove this identity's Kerberos tickets.", result);
}

+ (BOOL)changeKeychainAtPath:(NSString *)path oldPassword:(NSString *)oldPassword
               newPassword:(NSString *)newPassword error:(NSError **)error {
    // Unsupported implementation detail used by NoMAD, deliberately isolated.
    // Resolve it at runtime so an OS removal fails safely rather than preventing launch.
    typedef OSStatus (*ChangePassword)(SecKeychainRef, UInt32, const void *, UInt32, const void *);
    ChangePassword change = (ChangePassword)dlsym(RTLD_DEFAULT, "SecKeychainChangePassword");
    if (!change) return fail(error, @"This macOS version does not provide the legacy keychain password function.", 5);
    SecKeychainRef keychain = NULL;
    NSString *target = path ?: [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Keychains/login.keychain-db"];
    OSStatus status = SecKeychainOpen(target.fileSystemRepresentation, &keychain);
    if (status != errSecSuccess) return fail(error, @"Could not open the login keychain.", status);
    NSData *oldData = [oldPassword dataUsingEncoding:NSUTF8StringEncoding];
    NSData *newData = [newPassword dataUsingEncoding:NSUTF8StringEncoding];
    status = change(keychain, (UInt32)oldData.length, oldData.bytes, (UInt32)newData.length, newData.bytes);
    CFRelease(keychain);
    if (status != errSecSuccess) return fail(error, @"The login keychain password update could not be confirmed. Keep its previous password for repair.", status);
    return YES;
}

+ (BOOL)checkLoginKeychainWithError:(NSError **)error {
    if (!dlsym(RTLD_DEFAULT, "SecKeychainChangePassword"))
        return fail(error, @"This macOS version does not provide the legacy keychain password function. No password was changed.", 5);
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Keychains/login.keychain-db"];
    SecKeychainRef keychain = NULL;
    OSStatus status = SecKeychainOpen(path.fileSystemRepresentation, &keychain);
    if (status != errSecSuccess) return fail(error, @"Could not open the login keychain. No password was changed.", status);
    CFRelease(keychain);
    return YES;
}

+ (BOOL)probeKeychainWithError:(NSError **)error {
    NSString *folder = [NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
    if (![NSFileManager.defaultManager createDirectoryAtPath:folder withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    NSString *path = [folder stringByAppendingPathComponent:@"probe.keychain-db"];
    NSString *oldPassword = [@"old-\u00e9-" stringByAppendingString:NSUUID.UUID.UUIDString];
    NSString *newPassword = [@"new-\u96ea-" stringByAppendingString:NSUUID.UUID.UUIDString];
    NSData *oldData = [oldPassword dataUsingEncoding:NSUTF8StringEncoding];
    NSData *newData = [newPassword dataUsingEncoding:NSUTF8StringEncoding];
    SecKeychainRef keychain = NULL;
    OSStatus status = SecKeychainCreate(path.fileSystemRepresentation, (UInt32)oldData.length, oldData.bytes, NO, NULL, &keychain);
    BOOL ok = NO;
    if (status == errSecSuccess) {
        const char *secret = "preserve-this-item";
        status = SecKeychainAddGenericPassword(keychain, 8, "kerbside", 5, "probe", (UInt32)strlen(secret), secret, NULL);
        NSError *negativeError = nil;
        if (status != errSecSuccess) fail(error, @"Could not write the disposable keychain fixture.", status);
        else if ([self changeKeychainAtPath:path oldPassword:@"incorrect-password" newPassword:newPassword error:&negativeError]) {
            fail(error, @"Keychain probe failed: an incorrect old password was accepted. Do not use password sync on this OS.", 6);
        } else if ([self changeKeychainAtPath:path oldPassword:oldPassword newPassword:newPassword error:error]) {
            status = SecKeychainLock(keychain);
            CFRelease(keychain);
            keychain = NULL;
            if (status == errSecSuccess) status = SecKeychainOpen(path.fileSystemRepresentation, &keychain);
            SecKeychainStatus state = 0;
            if (status == errSecSuccess) status = SecKeychainGetStatus(keychain, &state);
            if (status != errSecSuccess || (state & kSecUnlockStateStatus)) {
                fail(error, @"Could not establish a locked, reopened disposable keychain.", status ?: 6);
            } else if (SecKeychainUnlock(keychain, (UInt32)oldData.length, oldData.bytes, YES) != errSecAuthFailed) {
                // Unlock behavior differs across macOS versions. A success here is
                // not evidence of compatibility: this negative control must fail.
                fail(error, @"The reopened disposable keychain did not reject its previous password. Password compatibility could not be verified.", 6);
            } else {
                status = SecKeychainUnlock(keychain, (UInt32)newData.length, newData.bytes, YES);
                if (status != errSecSuccess) {
                    fail(error, @"Could not unlock the disposable keychain with its new password.", status);
                } else {
                    UInt32 length = 0; void *bytes = NULL;
                    status = SecKeychainFindGenericPassword(keychain, 8, "kerbside", 5, "probe", &length, &bytes, NULL);
                    ok = status == errSecSuccess && length == strlen(secret) && memcmp(bytes, secret, length) == 0;
                    if (bytes) SecKeychainItemFreeContent(NULL, bytes);
                    if (!ok) fail(error, @"The disposable keychain item was not preserved after reopening.", status ?: 6);
                }
            }
        }
        if (keychain) {
            SecKeychainDelete(keychain);
            CFRelease(keychain);
        }
    } else fail(error, @"Could not create a disposable keychain.", status);
    [NSFileManager.defaultManager removeItemAtPath:folder error:nil];
    return ok;
}
@end
