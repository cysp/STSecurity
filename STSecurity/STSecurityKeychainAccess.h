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

#import <Foundation/Foundation.h>

#import "STSecurityRSAKey.h"


extern NSString * const STSecurityKeychainAccessErrorDomain;


typedef NS_ENUM(NSUInteger, STSecurityKeychainItemAccessibility) {
	STSecurityKeychainItemAccessibleWhenUnlocked = 0,
	STSecurityKeychainItemAccessibleWhenUnlockedThisDeviceOnly,
	STSecurityKeychainItemAccessibleAfterFirstUnlock,
	STSecurityKeychainItemAccessibleAfterFirstUnlockThisDeviceOnly,
	STSecurityKeychainItemAccessibleAlways,
	STSecurityKeychainItemAccessibleAlwaysThisDeviceOnly,
};

typedef NS_OPTIONS(NSInteger, STSecurityKeychainItemAccessControl) {
    STSecurityKeychainItemAccessControlRequireUserPresence = 0b1,
};


@protocol STSecurityKeychainAccessControlOptions <NSObject>
@property (nonatomic,copy) NSString *prompt;
@end

@interface STSecurityKeychainWritingOptions : NSObject
@property (nonatomic,assign) BOOL overwriteExisting;
@property (nonatomic,assign) STSecurityKeychainItemAccessibility accessibility;
@property (nonatomic,assign) NSInteger accessControl;
@property (nonatomic,copy) NSString *prompt;
@end


typedef void(^STSecurityKeychainAccessPasswordCompletionBlock)(NSString *password, NSError *error);
typedef void(^STSecurityKeychainAccessSuccessCompletionBlock)(BOOL success, NSError *error);


@interface STSecurityKeychainAccess : NSObject {}

#pragma mark - Password

+ (BOOL)containsPasswordForUsername:(NSString *)username service:(NSString *)service;
+ (BOOL)containsPasswordForUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing *)error;

+ (NSString *)passwordForUsername:(NSString *)username service:(NSString *)service;
+ (NSString *)passwordForUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing *)error;
+ (void)passwordForUsername:(NSString *)username service:(NSString *)service completion:(STSecurityKeychainAccessPasswordCompletionBlock)completion;

+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service;
+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing *)error;
+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service overwriteExisting:(BOOL)overwriteExisting;
+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service overwriteExisting:(BOOL)overwriteExisting error:(NSError * __autoreleasing *)error;
+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service withAccessibility:(enum STSecurityKeychainItemAccessibility)accessibility overwriteExisting:(BOOL)overwriteExisting error:(NSError * __autoreleasing *)error;
#if defined(__IPHONE_8_0)
+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service withAccessibility:(enum STSecurityKeychainItemAccessibility)accessibility accessControl:(NSInteger)accessControl overwriteExisting:(BOOL)overwriteExisting error:(NSError * __autoreleasing *)error;
#endif

+ (BOOL)deletePasswordForUsername:(NSString *)username service:(NSString *)service;
+ (BOOL)deletePasswordForUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing *)error;
+ (void)deletePasswordForUsername:(NSString *)username service:(NSString *)service completion:(STSecurityKeychainAccessSuccessCompletionBlock)completion;

+ (BOOL)deletePasswordsForService:(NSString *)service;
+ (BOOL)deletePasswordsForService:(NSString *)service error:(NSError * __autoreleasing *)error;
+ (void)deletePasswordsForService:(NSString *)service completion:(STSecurityKeychainAccessSuccessCompletionBlock)completion;


#pragma mark - RSA

+ (STSecurityRSAPublicKey *)fetchRSAPublicKeyForTag:(NSString *)tag;
+ (STSecurityRSAPublicKey *)fetchRSAPublicKeyForTag:(NSString *)tag error:(NSError * __autoreleasing *)error;
+ (STSecurityRSAPrivateKey *)fetchRSAPrivateKeyForTag:(NSString *)tag;
+ (STSecurityRSAPrivateKey *)fetchRSAPrivateKeyForTag:(NSString *)tag error:(NSError * __autoreleasing *)error;

+ (NSData *)fetchKeyDataForRSAPrivateKey:(STSecurityRSAPrivateKey *)key;
+ (NSData *)fetchKeyDataForRSAPrivateKey:(STSecurityRSAPrivateKey *)key error:(NSError * __autoreleasing *)error;

+ (BOOL)deleteRSAKeysForTag:(NSString *)tag;
+ (BOOL)deleteRSAKeysForTag:(NSString *)tag error:(NSError * __autoreleasing *)error;

+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithTag:(NSString *)tag;
+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithTag:(NSString *)tag publicKey:(STSecurityRSAPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityRSAPrivateKey * __autoreleasing *)privateKey;
+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithTag:(NSString *)tag publicKey:(STSecurityRSAPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityRSAPrivateKey * __autoreleasing *)privateKey error:(NSError * __autoreleasing *)error;
+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithAccessibility:(enum STSecurityKeychainItemAccessibility)accessibility tag:(NSString *)tag publicKey:(STSecurityRSAPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityRSAPrivateKey * __autoreleasing *)privateKey error:(NSError * __autoreleasing *)error;

+ (BOOL)insertRSAKeypairWithPublicKeyData:(NSData *)publicKeyData privateKeyData:(NSData *)privateKeyData intoKeychainWithAccessibility:(enum STSecurityKeychainItemAccessibility)accessibility tag:(NSString *)tag publicKey:(STSecurityRSAPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityRSAPrivateKey * __autoreleasing *)privateKey error:(NSError * __autoreleasing *)error;

@end
