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

#import "STSecurityKeychainAccess+Internal.h"
#import "STSecurityRSAKey+Internal.h"


@implementation STSecurityKeychainAccess (RSA)

#pragma mark - Retrieval

+ (STSecurityRSAPublicKey *)fetchRSAPublicKeyForTag:(NSString *)tag {
	return [self fetchRSAPublicKeyForTag:tag error:NULL];
}

+ (STSecurityRSAPublicKey *)fetchRSAPublicKeyForTag:(NSString *)tag error:(NSError * __autoreleasing *)error {
	if (error) {
		*error = nil;
	}

	if (!tag) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return nil;
	}

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

	STSecurityRSAPublicKey *key = [[STSecurityRSAPublicKey alloc] initWithKeyRef:keyRef keyData:keyData];

	if (keyRef) {
		CFRelease(keyRef);
		keyRef = NULL;
	}

	return key;
}

+ (STSecurityRSAPrivateKey *)fetchRSAPrivateKeyForTag:(NSString *)tag {
	return [self fetchRSAPrivateKeyForTag:tag error:NULL];
}

+ (STSecurityRSAPrivateKey *)fetchRSAPrivateKeyForTag:(NSString *)tag error:(NSError * __autoreleasing *)error {
	if (error) {
		*error = nil;
	}

	if (!tag) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return nil;
	}

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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
		keyRef = (SecKeyRef)result;
#pragma clang diagnostic pop
	}

	STSecurityRSAPrivateKey *key = [[STSecurityRSAPrivateKey alloc] initWithKeyRef:keyRef];

	if (keyRef) {
		CFRelease(keyRef);
		keyRef = NULL;
	}

	return key;
}

+ (NSData *)fetchKeyDataForRSAPrivateKey:(STSecurityRSAPrivateKey *)key {
	return [self fetchKeyDataForRSAPrivateKey:key error:nil];
}

+ (NSData *)fetchKeyDataForRSAPrivateKey:(STSecurityRSAPrivateKey *)key error:(NSError *__autoreleasing *)error {
	if (error) {
		*error = nil;
	}

	if (!key) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return nil;
	}

	SecKeyRef keyRef = key.keyRef;
	if (!keyRef) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return nil;
	}

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

+ (BOOL)deleteRSAKeysForTag:(NSString *)tag {
	return [self deleteRSAKeysForTag:tag error:NULL];
}

+ (BOOL)deleteRSAKeysForTag:(NSString *)tag error:(NSError * __autoreleasing *)error {
	if (error) {
		*error = nil;
	}

	if (!tag) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return NO;
	}

	NSDictionary * const query = @{
		(__bridge id)kSecClass: (__bridge id)kSecClassKey,
		(__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
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

+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size publicKey:(STSecurityRSAPublicKey *__autoreleasing *)publicKey privateKey:(STSecurityRSAPrivateKey *__autoreleasing *)privateKey {
	return [self generateRSAKeypairOfSize:size insertedIntoKeychainWithTag:nil publicKey:publicKey privateKey:privateKey];
}

+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithTag:(NSString *)tag {
	return [self generateRSAKeypairOfSize:size insertedIntoKeychainWithTag:tag publicKey:NULL privateKey:NULL];
}

+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithTag:(NSString *)tag publicKey:(STSecurityRSAPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityRSAPrivateKey * __autoreleasing *)privateKey {
	return [self generateRSAKeypairOfSize:size insertedIntoKeychainWithTag:tag publicKey:publicKey privateKey:privateKey error:NULL];
}

+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithTag:(NSString *)tag publicKey:(STSecurityRSAPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityRSAPrivateKey * __autoreleasing *)privateKey error:(NSError *__autoreleasing *)error {
	return [self generateRSAKeypairOfSize:size insertedIntoKeychainWithAccessibility:STSecurityKeychainItemAccessibleAlways tag:tag publicKey:publicKey privateKey:privateKey error:error];
}

+ (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithAccessibility:(enum STSecurityKeychainItemAccessibility)accessibility tag:(NSString *)tag publicKey:(STSecurityRSAPublicKey *__autoreleasing *)publicKey privateKey:(STSecurityRSAPrivateKey *__autoreleasing *)privateKey error:(NSError *__autoreleasing *)error {
	if (error) {
		*error = nil;
	}

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

	CFTypeRef const keychainItemAccessibility = STSecurityKeychainItemAccessibilityToCFType(accessibility);
	if (!keychainItemAccessibility) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return NO;
	}

	SecKeyRef publicKeyRef = NULL;
	SecKeyRef privateKeyRef = NULL;

	{
		NSMutableDictionary * const publicKeyAttrs = [NSMutableDictionary dictionary];
		if (tag) {
			publicKeyAttrs[(__bridge id)kSecAttrApplicationTag] = tag;
			publicKeyAttrs[(__bridge id)kSecAttrIsPermanent] = (__bridge id)kCFBooleanTrue;
		}
		NSMutableDictionary * const privateKeyAttrs = [NSMutableDictionary dictionary];
		if (tag) {
			privateKeyAttrs[(__bridge id)kSecAttrApplicationTag] = tag;
			privateKeyAttrs[(__bridge id)kSecAttrIsPermanent] = (__bridge id)kCFBooleanTrue;
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
		*publicKey = [[STSecurityRSAPublicKey alloc] initWithKeyRef:publicKeyRef keyData:publicKeyData];
	}
	if (privateKey) {
		*privateKey = [[STSecurityRSAPrivateKey alloc] initWithKeyRef:privateKeyRef];
	}

	if (publicKeyRef) {
		CFRelease(publicKeyRef);
		publicKeyRef = NULL;
	}
	if (privateKeyRef) {
		CFRelease(privateKeyRef);
		privateKeyRef = NULL;
	}

	return YES;
}


#pragma mark - Importing

+ (BOOL)insertRSAKeypairWithPublicKeyData:(NSData *)publicKeyData privateKeyData:(NSData *)privateKeyData intoKeychainWithAccessibility:(enum STSecurityKeychainItemAccessibility)accessibility tag:(NSString *)tag publicKey:(STSecurityRSAPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityRSAPrivateKey * __autoreleasing *)privateKey error:(NSError * __autoreleasing *)error {
	if (error) {
		*error = nil;
	}

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
	CFTypeRef const keychainItemAccessibility = STSecurityKeychainItemAccessibilityToCFType(accessibility);
	if (!keychainItemAccessibility) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return NO;
	}

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

		publicKeyData = [publicKeyData subdataWithRange:NSMakeRange(i, bytesLen - i)];
	} while (0);

	if (![publicKeyData length] || ![privateKeyData length]) {
		if (error) {
			// lying about error.code but it's close enough
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return NO;
	}

	SecKeyRef publicKeyRef = NULL;
	SecKeyRef privateKeyRef = NULL;
	{
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
		}

		NSMutableDictionary * const publicKeyAttrs = [NSMutableDictionary dictionaryWithDictionary:keyAttrs];
		publicKeyAttrs[(__bridge id)kSecAttrKeyClass] = (__bridge id)kSecAttrKeyClassPublic;
		publicKeyAttrs[(__bridge id)kSecValueData] = publicKeyData;
		publicKeyAttrs[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;

		NSMutableDictionary * const privateKeyAttrs = [NSMutableDictionary dictionaryWithDictionary:keyAttrs];
		privateKeyAttrs[(__bridge id)kSecAttrKeyClass] = (__bridge id)kSecAttrKeyClassPrivate;
		privateKeyAttrs[(__bridge id)kSecValueData] = privateKeyData;

		NSDictionary *publicKeyResult = nil;
		{
			CFTypeRef resultRef = NULL;
			OSStatus err = SecItemAdd((__bridge CFDictionaryRef)publicKeyAttrs, &resultRef);
			if (err != errSecSuccess) {
				if (error) {
					*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
				}
				return NO;
			}
			publicKeyResult = (__bridge_transfer NSDictionary *)resultRef;
		}

		NSDictionary *privateKeyResult = nil;
		{
			CFTypeRef resultRef = NULL;
			OSStatus err = SecItemAdd((__bridge CFDictionaryRef)privateKeyAttrs, &resultRef);
			if (err != errSecSuccess) {
				if (error) {
					*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
				}
				return NO;
			}
			privateKeyResult = (__bridge_transfer NSDictionary *)resultRef;
		}

		publicKeyRef = (__bridge_retained SecKeyRef)publicKeyResult[(__bridge id)kSecValueRef];
		publicKeyData = publicKeyResult[(__bridge id)kSecValueData];

		privateKeyRef = (__bridge_retained SecKeyRef)privateKeyResult[(__bridge id)kSecValueRef];
	}
	
	if (publicKey) {
		*publicKey = [[STSecurityRSAPublicKey alloc] initWithKeyRef:publicKeyRef keyData:publicKeyData];
	}
	if (privateKey) {
		*privateKey = [[STSecurityRSAPrivateKey alloc] initWithKeyRef:privateKeyRef];
	}
	
	if (publicKeyRef) {
		CFRelease(publicKeyRef);
		publicKeyRef = NULL;
	}
	if (privateKeyRef) {
		CFRelease(privateKeyRef);
		privateKeyRef = NULL;
	}
	
	return YES;
}

@end
