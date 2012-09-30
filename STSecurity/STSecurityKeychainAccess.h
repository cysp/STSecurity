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

#import "STSecurityKey.h"


extern NSString * const STSecurityKeychainAccessErrorDomain;


NS_ENUM(NSUInteger, STSecurityKeychainItemAccessibility) {
	STSecurityKeychainItemAccessibleWhenUnlocked = 0,
	STSecurityKeychainItemAccessibleWhenUnlockedThisDeviceOnly,
	STSecurityKeychainItemAccessibleAfterFirstUnlock,
	STSecurityKeychainItemAccessibleAfterFirstUnlockThisDeviceOnly,
	STSecurityKeychainItemAccessibleAlways,
	STSecurityKeychainItemAccessibleAlwaysThisDeviceOnly,
};


@interface STSecurityKeychainAccess : NSObject

+ (instancetype)keychainAccess;

- (STSecurityPublicKey *)fetchPublicKeyForTag:(NSString *)tag;
- (STSecurityPublicKey *)fetchPublicKeyForTag:(NSString *)tag error:(NSError * __autoreleasing *)error;
- (STSecurityPrivateKey *)fetchPrivateKeyForTag:(NSString *)tag;
- (STSecurityPrivateKey *)fetchPrivateKeyForTag:(NSString *)tag error:(NSError * __autoreleasing *)error;

- (BOOL)deleteKeyForTag:(NSString *)tag;
- (BOOL)deleteKeyForTag:(NSString *)tag error:(NSError * __autoreleasing *)error;

- (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithPublicKeyTag:(NSString *)publicKeyTag privateKeyTag:(NSString *)privateKeyTag;
- (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithPublicKeyTag:(NSString *)publicKeyTag privateKeyTag:(NSString *)privateKeyTag publicKey:(STSecurityPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityPrivateKey * __autoreleasing *)privateKey;
- (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithPublicKeyTag:(NSString *)publicKeyTag privateKeyTag:(NSString *)privateKeyTag publicKey:(STSecurityPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityPrivateKey * __autoreleasing *)privateKey error:(NSError * __autoreleasing *)error;
- (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithAccessGroup:(NSString *)accessGroup publicKeyTag:(NSString *)publicKeyTag privateKeyTag:(NSString *)privateKeyTag publicKey:(STSecurityPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityPrivateKey * __autoreleasing *)privateKey error:(NSError * __autoreleasing *)error;
- (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithAccessibility:(enum STSecurityKeychainItemAccessibility)accessibility accessGroup:(NSString *)accessGroup publicKeyTag:(NSString *)publicKeyTag privateKeyTag:(NSString *)privateKeyTag publicKey:(STSecurityPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityPrivateKey * __autoreleasing *)privateKey error:(NSError * __autoreleasing *)error;

@end
