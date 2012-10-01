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

+ (NSData *)fetchKeyDataForPrivateKey:(STSecurityPrivateKey *)key {
	return [self fetchKeyDataForPrivateKey:key error:nil];
}

+ (NSData *)fetchKeyDataForPrivateKey:(STSecurityPrivateKey *)key error:(NSError *__autoreleasing *)error {
	SecKeyRef keyRef = key.keyRef;

	NSDictionary * const query = @{
		(__bridge id)kSecClass: (__bridge id)kSecClassKey,
		(__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
		(__bridge id)kSecValueRef: (__bridge id)keyRef,
		(__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
	};

	NSData *keyData = nil;
	{
		CFTypeRef result = NULL;
		OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
		if (err != errSecSuccess) {
			if (error) {
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
			}
			return nil;
		}

		keyData = (__bridge_transfer NSData *)result;
	}

	return keyData;
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
	if (tag) {
		NSDictionary * const query = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassKey,
			(__bridge id)kSecAttrApplicationTag: tag,
		};
		OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);
		if (err == errSecSuccess) {
			if (error) {
				// lying about error.code but it's close enough
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecDuplicateItem userInfo:nil];
			}
			return NO;
		}
	}

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


#pragma mark - Importing

+ (BOOL)insertRSAKeypairWithPublicKeyData:(NSData *)publicKeyData privateKeyData:(NSData *)privateKeyData intoKeychainAccessibility:(enum STSecurityKeychainItemAccessibility)accessibility accessGroup:(NSString *)accessGroup tag:(NSString *)tag publicKey:(STSecurityPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityPrivateKey * __autoreleasing *)privateKey error:(NSError * __autoreleasing *)error {
	if (tag) {
		NSDictionary * const query = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassKey,
			(__bridge id)kSecAttrApplicationTag: tag,
		};
		OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);
		if (err == errSecSuccess) {
			if (error) {
				// lying about error.code but it's close enough
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecDuplicateItem userInfo:nil];
			}
			return NO;
		}
	}

	NSData *trimmedPublicKeyData = nil;
	do {
		const unsigned char *bytes = [publicKeyData bytes];
		const size_t bytesLen = [publicKeyData length];

		size_t i = 0;
		if (bytes[i++] != 0x30) {
			break;
		}

		i += (bytes[i] > 0x80) ? bytes[i] - 0x80 + 1 : 1;
		if (i >= bytesLen) {
			break;
		}

		if (bytes[i] != 0x30) {
			break;
		}

		i += 15;
		if (i >= bytesLen - 2) {
			break;
		}

		if (bytes[i++] != 0x03) {
			break;
		}

		i += (bytes[i] > 0x80) ? bytes[i] - 0x80 + 1 : 1;
		if (i >= bytesLen) {
			break;
		}

		if (bytes[i++] != 0x00) {
			break;
		}

		if (i >= bytesLen) {
			break;
		}

		trimmedPublicKeyData = [publicKeyData subdataWithRange:NSMakeRange(i, bytesLen - i)];
	} while (0);

	if (!trimmedPublicKeyData) {
		if (error) {
			// lying about error.code but it's close enough
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return NO;
	}

	SecKeyRef publicKeyRef = NULL;
	SecKeyRef privateKeyRef = NULL;
	{
		CFTypeRef keychainItemAccessibility = STSecurityKeychainItemAccessibilityToCFType(accessibility);

		NSMutableDictionary * const keyAttrs = [@{
			(__bridge id)kSecClass: (__bridge id)kSecClassKey,
												(__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
			(__bridge id)kSecAttrAccessible: (__bridge id)keychainItemAccessibility,
			(__bridge id)kSecReturnRef: (__bridge id)kCFBooleanTrue,
			(__bridge id)kSecReturnAttributes: (__bridge id)kCFBooleanTrue,
		} mutableCopy];
		if (tag) {
			keyAttrs[(__bridge id)kSecAttrApplicationTag] = tag;
			keyAttrs[(__bridge id)kSecAttrIsPermanent] = (__bridge id)kCFBooleanTrue;
			if (accessGroup) {
				keyAttrs[(__bridge id)kSecAttrAccessGroup] = accessGroup;
			}
		}

		NSMutableDictionary * const publicKeyAttrs = [NSMutableDictionary dictionaryWithDictionary:keyAttrs];
		publicKeyAttrs[(__bridge id)kSecAttrKeyClass] = (__bridge id)kSecAttrKeyClassPublic;
		publicKeyAttrs[(__bridge id)kSecValueData] = trimmedPublicKeyData;
		publicKeyAttrs[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;

		NSMutableDictionary * const privateKeyAttrs = [NSMutableDictionary dictionaryWithDictionary:keyAttrs];
		privateKeyAttrs[(__bridge id)kSecAttrKeyClass] = (__bridge id)kSecAttrKeyClassPrivate;
		privateKeyAttrs[(__bridge id)kSecValueData] = privateKeyData;

		{
			CFTypeRef resultRef = NULL;
			OSStatus err = SecItemAdd((__bridge CFDictionaryRef)publicKeyAttrs, &resultRef);
			if (err != errSecSuccess) {
				if (error) {
					*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
				}
				return NO;
			}
			NSDictionary * const result = (__bridge_transfer NSDictionary *)resultRef;
			publicKeyRef = (__bridge_retained SecKeyRef)result[(__bridge id)kSecValueRef];
			publicKeyData = result[(__bridge id)kSecValueData];
		}

		{
			CFTypeRef resultRef = NULL;
			OSStatus err = SecItemAdd((__bridge CFDictionaryRef)privateKeyAttrs, &resultRef);
			if (err != errSecSuccess) {
				if (error) {
					*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
				}
				return NO;
			}
			NSDictionary * const result = (__bridge_transfer NSDictionary *)resultRef;
			privateKeyRef = (__bridge_retained SecKeyRef)result[(__bridge id)kSecValueRef];
		}
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
