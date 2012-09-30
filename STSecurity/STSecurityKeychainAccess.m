//
//  STSecurityKeychainAccess.m
//  STSecurity
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import "STSecurityKeychainAccess.h"

#import <Security/Security.h>

#import "STSecurityKey.h"
#import "STSecurityKey+Internal.h"


NSString * const STSecurityKeychainAccessErrorDomain = @"STSecurityKeychainError";


CFTypeRef kSecAttrAccessibleWhenUnlocked;
CFTypeRef kSecAttrAccessibleAfterFirstUnlock;
CFTypeRef kSecAttrAccessibleAlways;
CFTypeRef kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
CFTypeRef kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
CFTypeRef kSecAttrAccessibleAlwaysThisDeviceOnly;


@implementation STSecurityKeychainAccess

#pragma mark - Instantiation

+ (instancetype)keychainAccess {
	return [[self alloc] init];
}


#pragma mark - Retrieval

- (STSecurityPublicKey *)fetchPublicKeyForTag:(NSString *)tag {
	return [self fetchPublicKeyForTag:tag error:NULL];
}

- (STSecurityPublicKey *)fetchPublicKeyForTag:(NSString *)tag error:(NSError * __autoreleasing *)error {
	NSDictionary * const query = @{
		(__bridge id)kSecClass: (__bridge id)kSecClassKey,
		(__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
		(__bridge id)kSecAttrApplicationTag: tag,
		(__bridge id)kSecReturnRef: (__bridge id)kCFBooleanTrue,
		(__bridge id)kSecReturnAttributes: (__bridge id)kCFBooleanTrue, // include attributes to work around bug (ref + data -> ref)
		(__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
	};

	NSDictionary *result = nil;
	{
		CFDictionaryRef resultDict = NULL;
		OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&resultDict);
		if (err != errSecSuccess) {
			if (error) {
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
			}
			return nil;
		}
		result = (__bridge_transfer NSDictionary *)resultDict;
	}

	SecKeyRef keyRef = (__bridge SecKeyRef)([result objectForKey:(__bridge id)(kSecValueRef)]);
	NSData *keyData = [result objectForKey:(__bridge id)(kSecValueData)];

	return [[STSecurityPublicKey alloc] initWithKeyRef:keyRef keyData:keyData];
}

- (STSecurityPrivateKey *)fetchPrivateKeyForTag:(NSString *)tag {
	return [self fetchPrivateKeyForTag:tag error:NULL];
}

- (STSecurityPrivateKey *)fetchPrivateKeyForTag:(NSString *)tag error:(NSError * __autoreleasing *)error {
	NSDictionary * const query = @{
		(__bridge id)kSecClass: (__bridge id)kSecClassKey,
		(__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
		(__bridge id)kSecAttrApplicationTag: tag,
		(__bridge id)kSecReturnRef: (__bridge id)kCFBooleanTrue,
		(__bridge id)kSecReturnAttributes: (__bridge id)kCFBooleanTrue, // include attributes to work around bug (ref + data -> ref)
		(__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
	};

	NSDictionary *result = nil;
	{
		CFDictionaryRef resultDict = NULL;
		OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&resultDict);
		if (err != errSecSuccess) {
			if (error) {
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
			}
			return nil;
		}

		result = (__bridge_transfer NSDictionary *)resultDict;
	}

	SecKeyRef keyRef = (__bridge SecKeyRef)([result objectForKey:(__bridge id)(kSecValueRef)]);

	return [[STSecurityPrivateKey alloc] initWithKeyRef:keyRef];
}


#pragma mark - Deletion

- (BOOL)deleteKeyForTag:(NSString *)tag {
	return [self deleteKeyForTag:tag error:NULL];
}

- (BOOL)deleteKeyForTag:(NSString *)tag error:(NSError * __autoreleasing *)error {
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

- (BOOL)generateRSAKeypairOfSize:(NSUInteger)size publicKey:(STSecurityPublicKey *__autoreleasing *)publicKey privateKey:(STSecurityPrivateKey *__autoreleasing *)privateKey {
	return [self generateRSAKeypairOfSize:size insertedIntoKeychainWithPublicKeyTag:nil privateKeyTag:nil publicKey:publicKey privateKey:privateKey];
}

- (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithPublicKeyTag:(NSString *)publicKeyTag privateKeyTag:(NSString *)privateKeyTag {
	return [self generateRSAKeypairOfSize:size insertedIntoKeychainWithPublicKeyTag:publicKeyTag privateKeyTag:privateKeyTag publicKey:NULL privateKey:NULL];
}

- (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithPublicKeyTag:(NSString *)publicKeyTag privateKeyTag:(NSString *)privateKeyTag publicKey:(STSecurityPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityPrivateKey * __autoreleasing *)privateKey {
	return [self generateRSAKeypairOfSize:size insertedIntoKeychainWithPublicKeyTag:publicKeyTag privateKeyTag:privateKeyTag publicKey:publicKey privateKey:privateKey error:NULL];
}

- (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithPublicKeyTag:(NSString *)publicKeyTag privateKeyTag:(NSString *)privateKeyTag publicKey:(STSecurityPublicKey * __autoreleasing *)publicKey privateKey:(STSecurityPrivateKey * __autoreleasing *)privateKey error:(NSError *__autoreleasing *)error {
	return [self generateRSAKeypairOfSize:size insertedIntoKeychainWithAccessGroup:nil publicKeyTag:publicKeyTag privateKeyTag:privateKeyTag publicKey:publicKey privateKey:privateKey error:error];
}

- (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithAccessGroup:(NSString *)accessGroup publicKeyTag:(NSString *)publicKeyTag privateKeyTag:(NSString *)privateKeyTag publicKey:(STSecurityPublicKey *__autoreleasing *)publicKey privateKey:(STSecurityPrivateKey *__autoreleasing *)privateKey error:(NSError *__autoreleasing *)error {
	return [self generateRSAKeypairOfSize:size insertedIntoKeychainWithAccessibility:STSecurityKeychainItemAccessibleWhenUnlocked accessGroup:accessGroup publicKeyTag:publicKeyTag privateKeyTag:privateKeyTag publicKey:publicKey privateKey:privateKey error:error];
}

- (BOOL)generateRSAKeypairOfSize:(NSUInteger)size insertedIntoKeychainWithAccessibility:(enum STSecurityKeychainItemAccessibility)accessibility accessGroup:(NSString *)accessGroup publicKeyTag:(NSString *)publicKeyTag privateKeyTag:(NSString *)privateKeyTag publicKey:(STSecurityPublicKey *__autoreleasing *)publicKey privateKey:(STSecurityPrivateKey *__autoreleasing *)privateKey error:(NSError *__autoreleasing *)error {
	if (publicKeyTag) {
		NSDictionary * const query = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassKey,
			(__bridge id)kSecAttrApplicationTag: publicKeyTag,
		};
		OSStatus err = SecItemDelete((__bridge CFDictionaryRef)query);
		if (err != errSecSuccess && err != errSecItemNotFound) {
			if (error) {
					*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
			}
			return NO;
		}
	}
	if (privateKeyTag) {
		NSDictionary * const query = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassKey,
			(__bridge id)kSecAttrApplicationTag: privateKeyTag,
		};
		OSStatus err = SecItemDelete((__bridge CFDictionaryRef)query);
		if (err != errSecSuccess && err != errSecItemNotFound) {
			if (error) {
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
			}
			return NO;
		}
	}

	SecKeyRef publicKeyRef = NULL;
	SecKeyRef privateKeyRef = NULL;

	{
		NSMutableDictionary * const publicKeyAttrs = [NSMutableDictionary dictionary];
		if (publicKeyTag) {
			publicKeyAttrs[(__bridge id)kSecAttrApplicationTag] = publicKeyTag;
			publicKeyAttrs[(__bridge id)kSecAttrIsPermanent] = (__bridge id)kCFBooleanTrue;
			if (accessGroup) {
				publicKeyAttrs[(__bridge id)kSecAttrAccessGroup] = accessGroup;
			}
		}
		NSMutableDictionary * const privateKeyAttrs = [NSMutableDictionary dictionary];
		if (privateKeyTag) {
			privateKeyAttrs[(__bridge id)kSecAttrApplicationTag] = privateKeyTag;
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
		};
		
		OSStatus err = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKeyRef, &privateKeyRef);
		if (err != errSecSuccess) {
			if (error) {
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
			}
			return NO;
		}
	}

	CFDataRef publicKeyDataRef = NULL;
	{
		NSDictionary *publicKeyDataQuery = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassKey,
			(__bridge id)kSecValueRef: (__bridge id)publicKeyRef,
			(__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
		};
		OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)publicKeyDataQuery, (CFTypeRef *)&publicKeyDataRef);
		if (err != errSecSuccess) {
			if (error) {
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
			}
			return NO;
		}
	}

	if (publicKey) {
		*publicKey = [[STSecurityPublicKey alloc] initWithKeyRef:publicKeyRef keyData:CFBridgingRelease(publicKeyDataRef)];
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
