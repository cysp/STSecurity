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


NS_ENUM(NSUInteger, STSecurityKeychainItemAccessibility) {
	STSecurityKeychainItemAccessibleWhenUnlocked = 0,
	STSecurityKeychainItemAccessibleWhenUnlockedThisDeviceOnly,
	STSecurityKeychainItemAccessibleAfterFirstUnlock,
	STSecurityKeychainItemAccessibleAfterFirstUnlockThisDeviceOnly,
	STSecurityKeychainItemAccessibleAlways,
	STSecurityKeychainItemAccessibleAlwaysThisDeviceOnly,
};


@interface STSecurityKeychainAccess : NSObject

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
+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithAccessGroup:(NSString *)accessGroup tag:(NSString *)tag publicKey:(STSecurityRSAPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityRSAPrivateKey * __autoreleasing *)privateKey error:(NSError * __autoreleasing *)error;
+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithAccessibility:(enum STSecurityKeychainItemAccessibility)accessibility accessGroup:(NSString *)accessGroup tag:(NSString *)tag publicKey:(STSecurityRSAPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityRSAPrivateKey * __autoreleasing *)privateKey error:(NSError * __autoreleasing *)error;

+ (BOOL)insertRSAKeypairWithPublicKeyData:(NSData *)publicKeyData privateKeyData:(NSData *)privateKeyData intoKeychainAccessibility:(enum STSecurityKeychainItemAccessibility)accessibility accessGroup:(NSString *)accessGroup tag:(NSString *)tag publicKey:(STSecurityRSAPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityRSAPrivateKey * __autoreleasing *)privateKey error:(NSError * __autoreleasing *)error;

@end
