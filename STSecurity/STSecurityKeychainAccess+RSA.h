//
//  STSecurityKeychainAccess.h
//  STSecurity
//
//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
//  Copyright © 2016 Scott Talbot. All rights reserved.
//

#import <STSecurity/STSecurity.h>


@interface STSecurityKeychainAccess (RSA)

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
