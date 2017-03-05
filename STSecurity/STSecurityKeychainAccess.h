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

typedef NS_OPTIONS(NSInteger, STSecurityKeychainItemAccessControl) {
	STSecurityKeychainItemAccessControlRequireUserPresence = 0b1,
};

@protocol STSecurityKeychainReadingOptions <NSObject>
@property (nonatomic,copy,readonly) NSString *prompt;
@end
@interface STSecurityKeychainReadingOptions : NSObject<STSecurityKeychainReadingOptions>
@property (nonatomic,copy) NSString *prompt;
@end

@protocol STSecurityKeychainWritingOptions <NSObject>
@property (nonatomic,assign,readonly) BOOL overwriteExisting;
@property (nonatomic,assign,readonly) STSecurityKeychainItemAccessibility accessibility;
@property (nonatomic,assign,readonly) NSInteger accessControl;
@property (nonatomic,copy,readonly) NSString *prompt;
@end
@interface STSecurityKeychainWritingOptions : NSObject<STSecurityKeychainWritingOptions>
@property (nonatomic,assign) BOOL overwriteExisting;
@property (nonatomic,assign) STSecurityKeychainItemAccessibility accessibility;
@property (nonatomic,assign) NSInteger accessControl;
@property (nonatomic,copy) NSString *prompt;
@end


@interface STSecurityKeychainAccess : NSObject {}

#pragma mark - Password

+ (BOOL)containsPasswordForUsername:(NSString *)username service:(NSString *)service;
+ (BOOL)containsPasswordForUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing *)error;

+ (NSString *)passwordForUsername:(NSString *)username service:(NSString *)service;
+ (NSString *)passwordForUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing *)error;
+ (NSString *)passwordForUsername:(NSString *)username service:(NSString *)service withOptions:(id<STSecurityKeychainReadingOptions>)options error:(NSError * __autoreleasing *)error;

+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service;
+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing *)error;
+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service overwriteExisting:(BOOL)overwriteExisting;
+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service overwriteExisting:(BOOL)overwriteExisting error:(NSError * __autoreleasing *)error;
+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service withOptions:(id<STSecurityKeychainWritingOptions>)options error:(NSError * __autoreleasing *)error;

+ (BOOL)deletePasswordForUsername:(NSString *)username service:(NSString *)service;
+ (BOOL)deletePasswordForUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing *)error;
+ (BOOL)deletePasswordForUsername:(NSString *)username service:(NSString *)service withOptions:(id<STSecurityKeychainWritingOptions>)options error:(NSError * __autoreleasing *)error;

+ (BOOL)deletePasswordsForService:(NSString *)service;
+ (BOOL)deletePasswordsForService:(NSString *)service error:(NSError * __autoreleasing *)error;
+ (BOOL)deletePasswordsForService:(NSString *)service withOptions:(id<STSecurityKeychainWritingOptions>)options error:(NSError * __autoreleasing *)error;

@end
