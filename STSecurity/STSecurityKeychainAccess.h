//
//  STSecurityKeychainAccess.h
//  STSecurity
//
//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

@import Foundation;

#import <STSecurity/STSecurity.h>

NS_ASSUME_NONNULL_BEGIN


extern NSString * const STSecurityKeychainAccessErrorDomain;


typedef NS_ENUM(NSUInteger, STSecurityKeychainItemAccessibility) {
	STSecurityKeychainItemAccessibleWhenUnlocked = 0,
	STSecurityKeychainItemAccessibleWhenUnlockedThisDeviceOnly,
	STSecurityKeychainItemAccessibleAfterFirstUnlock,
	STSecurityKeychainItemAccessibleAfterFirstUnlockThisDeviceOnly,
	STSecurityKeychainItemAccessibleAlways,
	STSecurityKeychainItemAccessibleAlwaysThisDeviceOnly,
	STSecurityKeychainItemAccessibleWhenPasscodeSetThisDeviceOnly,
};

typedef NS_OPTIONS(NSUInteger, STSecurityKeychainItemAccessControl) {
	STSecurityKeychainItemAccessControlNone = 0,
	/// User presence policy using Touch ID or Passcode. Touch ID does not have to be available or enrolled. Item is still accessible by Touch ID even if fingers are added or removed.
	STSecurityKeychainItemAccessControlRequireUserPresence = 1 << 0,
	/// Constraint: Touch ID (any finger). Touch ID must be available and at least one finger must be enrolled. Item is still accessible by Touch ID even if fingers are added or removed.
	STSecurityKeychainItemAccessControlTouchIDAny = 1 << 1,
	/// Constraint: Touch ID from the set of currently enrolled fingers. Touch ID must be available and at least one finger must be enrolled. When fingers are added or removed, the item is invalidated.
	STSecurityKeychainItemAccessControlTouchIDCurrentSet = 1 << 3,
	/// Constraint: Device passcode
	STSecurityKeychainItemAccessControlDevicePasscode = 1 << 4,
	/// Constraint logic operation: when using more than one constraint, at least one of them must be satisfied.
	STSecurityKeychainItemAccessControlOr = 1 << 14,
	/// Constraint logic operation: when using more than one constraint, all must be satisfied.
	STSecurityKeychainItemAccessControlAnd = 1 << 15,
	/// Create access control for private key operations (i.e. sign operation)
	STSecurityKeychainItemAccessControlPrivateKeyUsage = 1 << 30,
	/// Security: Application provided password for data encryption key generation. This is not a constraint but additional item encryption mechanism.
	STSecurityKeychainItemAccessControlApplicationPassword = 0x80000000,
};

@protocol STSecurityKeychainReadingOptions <NSObject>
@property (nonatomic,copy,readonly,nullable) NSString *prompt;
@end
@interface STSecurityKeychainReadingOptions : NSObject<STSecurityKeychainReadingOptions>
- (instancetype)init NS_REFINED_FOR_SWIFT;
@property (nonatomic,copy,nullable) NSString *prompt;
@end

@protocol STSecurityKeychainWritingOptions <NSObject>
@property (nonatomic,assign,readonly) BOOL overwriteExisting;
@property (nonatomic,assign,readonly) STSecurityKeychainItemAccessibility accessibility;
@property (nonatomic,assign,readonly) STSecurityKeychainItemAccessControl accessControl;
@property (nonatomic,copy,readonly,nullable) NSString *prompt;
@end
@interface STSecurityKeychainWritingOptions : NSObject<STSecurityKeychainWritingOptions>
- (instancetype)init NS_REFINED_FOR_SWIFT;
@property (nonatomic,assign) BOOL overwriteExisting;
@property (nonatomic,assign) STSecurityKeychainItemAccessibility accessibility;
@property (nonatomic,assign) STSecurityKeychainItemAccessControl accessControl;
@property (nonatomic,copy,nullable) NSString *prompt;
@end


@interface STSecurityKeychainAccess : NSObject {}

#pragma mark - Password

+ (BOOL)containsPasswordForUsername:(NSString *)username service:(NSString *)service NS_SWIFT_UNAVAILABLE("");
+ (BOOL)containsPasswordForUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing __nullable * __nullable)error NS_SWIFT_NOTHROW NS_REFINED_FOR_SWIFT;

+ (NSString * __nullable)passwordForUsername:(NSString *)username service:(NSString *)service NS_SWIFT_UNAVAILABLE("");
+ (NSString * __nullable)passwordForUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing __nullable * __nullable)error NS_SWIFT_UNAVAILABLE("");
+ (NSString * __nullable)passwordForUsername:(NSString *)username service:(NSString *)service withOptions:(id<STSecurityKeychainReadingOptions> __nullable)options error:(NSError * __autoreleasing __nullable * __nullable)error NS_REFINED_FOR_SWIFT;

+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service NS_SWIFT_UNAVAILABLE("");
+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing __nullable * __nullable)error NS_SWIFT_UNAVAILABLE("");
+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service overwriteExisting:(BOOL)overwriteExisting NS_SWIFT_UNAVAILABLE("");
+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service overwriteExisting:(BOOL)overwriteExisting error:(NSError * __autoreleasing __nullable * __nullable)error NS_SWIFT_UNAVAILABLE("");
+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service withOptions:(id<STSecurityKeychainWritingOptions> __nullable)options error:(NSError * __autoreleasing __nullable * __nullable)error NS_REFINED_FOR_SWIFT;

+ (BOOL)deletePasswordForUsername:(NSString *)username service:(NSString *)service NS_SWIFT_UNAVAILABLE("");
+ (BOOL)deletePasswordForUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing __nullable * __nullable)error NS_SWIFT_UNAVAILABLE("");
+ (BOOL)deletePasswordForUsername:(NSString *)username service:(NSString *)service withOptions:(id<STSecurityKeychainWritingOptions> __nullable)options error:(NSError * __autoreleasing __nullable * __nullable)error NS_REFINED_FOR_SWIFT;

+ (BOOL)deletePasswordsForService:(NSString *)service NS_SWIFT_UNAVAILABLE("");
+ (BOOL)deletePasswordsForService:(NSString *)service error:(NSError * __autoreleasing __nullable * __nullable)error NS_SWIFT_UNAVAILABLE("");
+ (BOOL)deletePasswordsForService:(NSString *)service withOptions:(id<STSecurityKeychainWritingOptions> __nullable)options error:(NSError * __autoreleasing __nullable * __nullable)error NS_REFINED_FOR_SWIFT;

@end


NS_ASSUME_NONNULL_END
