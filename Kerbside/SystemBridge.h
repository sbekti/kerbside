#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
@interface SystemBridge : NSObject
+ (nullable NSArray<NSString *> *)controllersForDomain:(NSString *)domain error:(NSError **)error
    NS_SWIFT_NAME(controllers(domain:));
+ (BOOL)authenticatePrincipal:(NSString *)principal password:(NSString *)password error:(NSError **)error
    NS_SWIFT_NAME(authenticate(principal:password:));
+ (BOOL)changePasswordForPrincipal:(NSString *)principal oldPassword:(NSString *)oldPassword
                      newPassword:(NSString *)newPassword error:(NSError **)error
    NS_SWIFT_NAME(changePassword(principal:oldPassword:newPassword:));
+ (nullable NSString *)cacheNameForPrincipal:(NSString *)principal;
+ (nullable NSDate *)ticketExpiryForPrincipal:(NSString *)principal;
+ (BOOL)signOutPrincipal:(NSString *)principal error:(NSError **)error NS_SWIFT_NAME(signOut(principal:));
+ (BOOL)changeKeychainAtPath:(nullable NSString *)path oldPassword:(NSString *)oldPassword
               newPassword:(NSString *)newPassword error:(NSError **)error
    NS_SWIFT_NAME(changeKeychain(path:oldPassword:newPassword:));
+ (BOOL)checkLoginKeychainWithError:(NSError **)error NS_SWIFT_NAME(checkLoginKeychain());
+ (BOOL)probeKeychainWithError:(NSError **)error NS_SWIFT_NAME(probeKeychain());
@end
NS_ASSUME_NONNULL_END
