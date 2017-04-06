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

NS_ASSUME_NONNULL_BEGIN


@interface STSecurityKeychainAccess (RSA)

+ (STSecurityRSAPublicKey * __nullable)fetchRSAPublicKeyForTag:(NSString *)tag NS_SWIFT_UNAVAILABLE("");
+ (STSecurityRSAPublicKey * __nullable)fetchRSAPublicKeyForTag:(NSString *)tag error:(NSError * __autoreleasing __nullable * __nullable)error;
+ (STSecurityRSAPrivateKey * __nullable)fetchRSAPrivateKeyForTag:(NSString *)tag NS_SWIFT_UNAVAILABLE("");
+ (STSecurityRSAPrivateKey * __nullable)fetchRSAPrivateKeyForTag:(NSString *)tag error:(NSError * __autoreleasing __nullable * __nullable)error;

+ (NSData * __nullable)fetchKeyDataForRSAPrivateKey:(STSecurityRSAPrivateKey *)key NS_SWIFT_UNAVAILABLE("");
+ (NSData * __nullable)fetchKeyDataForRSAPrivateKey:(STSecurityRSAPrivateKey *)key error:(NSError * __autoreleasing __nullable * __nullable)error;

+ (BOOL)deleteRSAKeysForTag:(NSString *)tag NS_SWIFT_UNAVAILABLE("");
+ (BOOL)deleteRSAKeysForTag:(NSString *)tag error:(NSError * __autoreleasing __nullable * __nullable)error;

+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithTag:(NSString *)tag;
+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithTag:(NSString * __nullable)tag publicKey:(STSecurityRSAPublicKey * __autoreleasing __nonnull * __nullable)publicKey privateKey:(STSecurityRSAPrivateKey * __autoreleasing __nonnull * __nullable)privateKey;
+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithTag:(NSString * __nullable)tag publicKey:(STSecurityRSAPublicKey * __autoreleasing __nonnull * __nullable)publicKey privateKey:(STSecurityRSAPrivateKey * __autoreleasing __nonnull * __nullable)privateKey error:(NSError * __autoreleasing __nullable * __nullable)error;
+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithAccessibility:(enum STSecurityKeychainItemAccessibility)accessibility tag:(NSString * __nullable)tag publicKey:(STSecurityRSAPublicKey * __autoreleasing __nonnull * __nullable)publicKey privateKey:(STSecurityRSAPrivateKey * __autoreleasing __nonnull * __nullable)privateKey error:(NSError * __autoreleasing __nullable * __nullable)error;

+ (BOOL)insertRSAKeypairWithPublicKeyData:(NSData *)publicKeyData privateKeyData:(NSData *)privateKeyData intoKeychainWithAccessibility:(enum STSecurityKeychainItemAccessibility)accessibility tag:(NSString * __nullable)tag publicKey:(STSecurityRSAPublicKey * __autoreleasing __nonnull * __nullable)publicKey privateKey:(STSecurityRSAPrivateKey * __autoreleasing __nonnull * __nullable)privateKey error:(NSError * __autoreleasing __nullable * __nullable)error;

@end

NS_ASSUME_NONNULL_END
