//
//  STSecurityKeychainAccess.m
//  STSecurity
//
//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import "STSecurityKeychainAccess.h"

#import <Security/Security.h>

#import "STSecurityKey.h"
#import "STSecurityKey+Internal.h"


NSString * const STSecurityKeychainAccessErrorDomain = @"STSecurityKeychainError";


static inline CFTypeRef STSecurityKeychainItemAccessibilityToCFType(enum STSecurityKeychainItemAccessibility accessibility) {
	switch (accessibility) {
		case STSecurityKeychainItemAccessibleWhenUnlocked:
			return kSecAttrAccessibleWhenUnlocked;
		case STSecurityKeychainItemAccessibleWhenUnlockedThisDeviceOnly:
			return kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
		case STSecurityKeychainItemAccessibleAfterFirstUnlock:
			return kSecAttrAccessibleAfterFirstUnlock;
		case STSecurityKeychainItemAccessibleAfterFirstUnlockThisDeviceOnly:
			return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
		case STSecurityKeychainItemAccessibleAlways:
			return kSecAttrAccessibleAlways;
		case STSecurityKeychainItemAccessibleAlwaysThisDeviceOnly:
			return kSecAttrAccessibleAlwaysThisDeviceOnly;
	}
	NSCAssert(0, @"unreachable", nil);
	return kSecAttrAccessibleWhenUnlocked;
}


@implementation STSecurityKeychainAccess

#pragma mark - Retrieval

+ (STSecurityPublicKey *)fetchPublicKeyForTag:(NSString *)tag {
	return [self fetchPublicKeyForTag:tag error:NULL];
}

+ (STSecurityPublicKey *)fetchPublicKeyForTag:(NSString *)tag error:(NSError * __autoreleasing *)error {
	NSDictionary * const query = @{
		(__bridge id)kSecClass: (__bridge id)kSecClassKey,
		(__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
		(__bridge id)kSecAttrApplicationTag: tag,
		(__bridge id)kSecReturnRef: (__bridge id)kCFBooleanTrue,
		(__bridge id)kSecReturnAttributes: (__bridge id)kCFBooleanTrue, // include attributes to work around bug (ref + data -> ref)
		(__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
	};

	SecKeyRef keyRef = NULL;
	NSData *keyData = nil;
	{
		CFDictionaryRef resultDict = NULL;
		OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&resultDict);
		if (err != errSecSuccess) {
			if (error) {
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
			}
			return nil;
		}

		NSDictionary *result = (__bridge_transfer NSDictionary *)resultDict;

		keyRef = (__bridge_retained SecKeyRef)[result objectForKey:(__bridge id)kSecValueRef];
		keyData = [result objectForKey:(__bridge id)kSecValueData];
	}

	STSecurityPublicKey *key = [[STSecurityPublicKey alloc] initWithKeyRef:keyRef keyData:keyData];

	if (keyRef) {
		CFRelease(keyRef), keyRef = NULL;
	}

	return key;
}

+ (STSecurityPrivateKey *)fetchPrivateKeyForTag:(NSString *)tag {
	return [self fetchPrivateKeyForTag:tag error:NULL];
}

+ (STSecurityPrivateKey *)fetchPrivateKeyForTag:(NSString *)tag error:(NSError * __autoreleasing *)error {
	NSDictionary * const query = @{
		(__bridge id)kSecClass: (__bridge id)kSecClassKey,
		(__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
		(__bridge id)kSecAttrApplicationTag: tag,
		(__bridge id)kSecReturnRef: (__bridge id)kCFBooleanTrue,
	};

	SecKeyRef keyRef = NULL;
	{
		CFTypeRef result = NULL;
		OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
		if (err != errSecSuccess) {
			if (error) {
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
			}
			return nil;
		}

		keyRef = (SecKeyRef)result;
	}

	STSecurityPrivateKey *key = [[STSecurityPrivateKey alloc] initWithKeyRef:keyRef];

	if (keyRef) {
		CFRelease(keyRef), keyRef = NULL;
	}

	return key;
}


#pragma mark - Deletion

+ (BOOL)deleteKeysForTag:(NSString *)tag {
	return [self deleteKeysForTag:tag error:NULL];
}

+ (BOOL)deleteKeysForTag:(NSString *)tag error:(NSError * __autoreleasing *)error {
	NSDictionary * const query = @{
		(__bridge id)kSecClass: (__bridge id)kSecClassKey,
		(__bridge id)kSecAttrApplicationTag: tag,
	};

	OSStatus err = SecItemDelete((__bridge CFDictionaryRef)query);
	if (err != errSecSuccess) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
		}
		return NO;
	}

	return YES;
}


#pragma mark - Generation

+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size publicKey:(STSecurityPublicKey *__autoreleasing *)publicKey privateKey:(STSecurityPrivateKey *__autoreleasing *)privateKey {
	return [self generateRSAKeypairOfSize:size insertedIntoKeychainWithTag:nil publicKey:publicKey privateKey:privateKey];
}

+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithTag:(NSString *)tag {
	return [self generateRSAKeypairOfSize:size insertedIntoKeychainWithTag:tag publicKey:NULL privateKey:NULL];
}

+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithTag:(NSString *)tag publicKey:(STSecurityPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityPrivateKey * __autoreleasing *)privateKey {
	return [self generateRSAKeypairOfSize:size insertedIntoKeychainWithTag:tag publicKey:publicKey privateKey:privateKey error:NULL];
}

+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithTag:(NSString *)tag publicKey:(STSecurityPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityPrivateKey * __autoreleasing *)privateKey error:(NSError *__autoreleasing *)error {
	return [self generateRSAKeypairOfSize:size insertedIntoKeychainWithAccessGroup:nil tag:tag publicKey:publicKey privateKey:privateKey error:error];
}

+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithAccessGroup:(NSString *)accessGroup tag:(NSString *)tag publicKey:(STSecurityPublicKey *__autoreleasing *)publicKey privateKey:(STSecurityPrivateKey *__autoreleasing *)privateKey error:(NSError *__autoreleasing *)error {
	return [self generateRSAKeypairOfSize:size insertedIntoKeychainWithAccessibility:STSecurityKeychainItemAccessibleWhenUnlocked accessGroup:accessGroup tag:tag publicKey:publicKey privateKey:privateKey error:error];
}

+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithAccessibility:(enum STSecurityKeychainItemAccessibility)accessibility accessGroup:(NSString *)accessGroup tag:(NSString *)tag publicKey:(STSecurityPublicKey *__autoreleasing *)publicKey privateKey:(STSecurityPrivateKey *__autoreleasing *)privateKey error:(NSError *__autoreleasing *)error {
	SecKeyRef publicKeyRef = NULL;
	SecKeyRef privateKeyRef = NULL;

	{
		CFTypeRef keychainItemAccessibility = STSecurityKeychainItemAccessibilityToCFType(accessibility);

		NSMutableDictionary * const publicKeyAttrs = [NSMutableDictionary dictionary];
		if (tag) {
			publicKeyAttrs[(__bridge id)kSecAttrApplicationTag] = tag;
			publicKeyAttrs[(__bridge id)kSecAttrIsPermanent] = (__bridge id)kCFBooleanTrue;
			if (accessGroup) {
				publicKeyAttrs[(__bridge id)kSecAttrAccessGroup] = accessGroup;
			}
		}
		NSMutableDictionary * const privateKeyAttrs = [NSMutableDictionary dictionary];
		if (tag) {
			privateKeyAttrs[(__bridge id)kSecAttrApplicationTag] = tag;
			privateKeyAttrs[(__bridge id)kSecAttrIsPermanent] = (__bridge id)kCFBooleanTrue;
			if (accessGroup) {
				privateKeyAttrs[(__bridge id)kSecAttrAccessGroup] = accessGroup;
			}
		}
		NSDictionary * const parameters = @{
			(__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
			(__bridge id)kSecAttrKeySizeInBits: @(size),
			(__bridge id)kSecPublicKeyAttrs: publicKeyAttrs,
			(__bridge id)kSecPrivateKeyAttrs: privateKeyAttrs,
			(__bridge id)kSecAttrAccessible: (__bridge id)keychainItemAccessibility,
		};
		
		OSStatus err = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKeyRef, &privateKeyRef);
		if (err != errSecSuccess) {
			if (error) {
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
			}
			return NO;
		}
	}

	NSData *publicKeyData = nil;
	{
		CFTypeRef result = NULL;
		NSDictionary *publicKeyDataQuery = @{
		(__bridge id)kSecClass: (__bridge id)kSecClassKey,
		(__bridge id)kSecValueRef: (__bridge id)publicKeyRef,
		(__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
		};
		OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)publicKeyDataQuery, &result);
		if (err != errSecSuccess) {
			if (error) {
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
			}
			return NO;
		}

		publicKeyData = (__bridge_transfer NSData *)result;
	}

	if (publicKey) {
		*publicKey = [[STSecurityPublicKey alloc] initWithKeyRef:publicKeyRef keyData:publicKeyData];
	}
	if (privateKey) {
		*privateKey = [[STSecurityPrivateKey alloc] initWithKeyRef:privateKeyRef];
	}

	if (publicKeyRef) {
		CFRelease(publicKeyRef), publicKeyRef = NULL;
	}
	if (privateKeyRef) {
		CFRelease(privateKeyRef), privateKeyRef = NULL;
	}

	return YES;
}

@end
