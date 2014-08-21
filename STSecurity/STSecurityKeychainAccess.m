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

#if ! (defined(__has_feature) && __has_feature(objc_arc))
# error "STSecurity must be compiled with ARC enabled"
#endif


#import "STSecurityKeychainAccess.h"

#import <Security/Security.h>

#import "STSecurityRSAKey.h"
#import "STSecurityRSAKey+Internal.h"


NSString * const STSecurityKeychainAccessErrorDomain = @"STSecurityKeychainError";


@implementation STSecurityKeychainReadingOptions
@synthesize prompt = _prompt;
@end

@implementation STSecurityKeychainWritingOptions
@synthesize overwriteExisting = _overwriteExisting;
@synthesize accessibility = _accessibility;
#if defined(__IPHONE_8_0)
@synthesize accessControl = _accessControl;
#endif
@synthesize prompt = _prompt;
@end


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
#if defined(__IPHONE_8_0)
		case STSecurityKeychainItemAccessibleWhenPasscodeSetThisDeviceOnly:
			return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly;
#endif
	}
	NSCAssert(0, @"unreachable", nil);
	return kSecAttrAccessibleWhenUnlocked;
}


@implementation STSecurityKeychainAccess

#pragma mark - Password - Presence

+ (BOOL)containsPasswordForUsername:(NSString *)username service:(NSString *)service {
	return [self containsPasswordForUsername:username service:service error:NULL];
}

+ (BOOL)containsPasswordForUsername:(NSString *)username service:(NSString *)service error:(NSError *__autoreleasing *)error {
	if (error) {
		*error = nil;
	}

	if (![username length] || ![service length]) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return NO;
	}

	NSDictionary *attributes = nil;

	{
		NSMutableDictionary *query = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			(__bridge id)kSecAttrService: service,
			(__bridge id)kSecAttrAccount: username,
			(__bridge id)kSecReturnAttributes: (__bridge id)kCFBooleanTrue,
		}.mutableCopy;
#if defined(__IPHONE_8_0)
		if (&kSecUseNoAuthenticationUI) {
			query[(__bridge id)kSecUseNoAuthenticationUI] = (__bridge id)kCFBooleanTrue;
		}
#endif
		CFDictionaryRef result = NULL;
		OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
		if (err == errSecItemNotFound) {
		} else if (err == errSecSuccess) {
			attributes = (__bridge_transfer NSDictionary *)result;
		} else if (err == errSecInteractionNotAllowed) {
			attributes = (__bridge_transfer NSDictionary *)result ?: @{};
		} else {
			if (error) {
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
			}
			return NO;
		}
	}

	return !!attributes;
}

#pragma mark - Password - Insertion

+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service {
	return [self setPassword:password forUsername:username service:service withOptions:nil error:NULL];
}

+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing *)error {
	return [self setPassword:password forUsername:username service:service withOptions:nil error:error];
}

+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service overwriteExisting:(BOOL)overwriteExisting {
	return [self setPassword:password forUsername:username service:service overwriteExisting:overwriteExisting error:NULL];
}

+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service overwriteExisting:(BOOL)overwriteExisting error:(NSError * __autoreleasing *)error {
	STSecurityKeychainWritingOptions * const options = [[STSecurityKeychainWritingOptions alloc] init];
	options.overwriteExisting = overwriteExisting;
	return [self setPassword:password forUsername:username service:service withOptions:options error:error];
}

+ (BOOL)setPassword:(NSString *)password forUsername:(NSString *)username service:(NSString *)service withOptions:(id<STSecurityKeychainWritingOptions>)options error:(NSError *__autoreleasing *)error {
	if (error) {
		*error = nil;
	}

	if (![username length] || ![service length]) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return NO;
	}

	NSData * const passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
	if (![passwordData length]) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return NO;
	}

	BOOL shouldUpdate = NO;
	NSData *persistentRef = nil;

	{
		NSMutableDictionary * const query = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			(__bridge id)kSecAttrService: service,
			(__bridge id)kSecAttrAccount: username,
			(__bridge id)kSecReturnPersistentRef: (__bridge id)kCFBooleanTrue,
		}.mutableCopy;
#if defined(__IPHONE_8_0)
		if (&kSecUseNoAuthenticationUI) {
			query[(__bridge id)kSecUseNoAuthenticationUI] = (__bridge id)kCFBooleanTrue;
		}
#endif
		CFDataRef result = NULL;
		OSStatus const err = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
		if (err == errSecInteractionNotAllowed) {
			shouldUpdate = YES;
		}
		if (err == errSecSuccess) {
			shouldUpdate = YES;
			persistentRef = (__bridge_transfer NSData *)result;
		}
	}
	if (shouldUpdate && !options.overwriteExisting) {
		if (error) {
			// lying about error.code but pretty close
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecDuplicateItem userInfo:nil];
		}
		return NO;
	}

	CFTypeRef const accessibilityRef = STSecurityKeychainItemAccessibilityToCFType(options.accessibility);
	if (!accessibilityRef) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return NO;
	}
	CFTypeRef accessControlRef = NULL;
#if defined(__IPHONE_8_0)
	if (&SecAccessControlCreateWithFlags) {
		accessControlRef = SecAccessControlCreateWithFlags(NULL, accessibilityRef, (SecAccessControlCreateFlags)options.accessControl, NULL);
		if (!accessControlRef) {
			if (error) {
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
			}
			return NO;
		}
	}
#endif

	NSMutableDictionary * const attributes = @{
		(__bridge id)kSecValueData: passwordData,
	}.mutableCopy;
#if defined(__IPHONE_8_0)
	if (&kSecAttrAccessControl && accessControlRef) {
		attributes[(__bridge id)kSecAttrAccessControl] = (__bridge id)accessControlRef;
	} else
#endif
	{
		attributes[(__bridge id)kSecAttrAccessible] = (__bridge id)accessibilityRef;
	}
	if (accessControlRef) {
		CFRelease(accessControlRef), accessControlRef = NULL;
	}

	if (shouldUpdate) {
		NSMutableDictionary * const query = @{}.mutableCopy;
		if (persistentRef) {
			query[(__bridge id)kSecValuePersistentRef] = persistentRef;
		} else {
			query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
			query[(__bridge id)kSecAttrService] = service;
			query[(__bridge id)kSecAttrAccount] = username;
		}

#if defined(__IPHONE_8_0)
		if (&kSecUseOperationPrompt && options.prompt.length) {
			query[(__bridge id)kSecUseOperationPrompt] = options.prompt;
		}
#else
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return NO;
#endif

		OSStatus const err = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributes);
		if (err == errSecSuccess) {
			return YES;
		}
		if (err != errSecItemNotFound) {
			if (error) {
				*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
			}
			return NO;
		}
	}

	attributes[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
	attributes[(__bridge id)kSecAttrService] = service;
	attributes[(__bridge id)kSecAttrAccount] = username;
	OSStatus const err = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);
	if (err != errSecSuccess) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
		}
		return NO;
	}

	return YES;
}


#pragma mark - Password - Retrieval

+ (NSString *)passwordForUsername:(NSString *)username service:(NSString *)service {
	return [self passwordForUsername:username service:service withOptions:nil error:NULL];
}

+ (NSString *)passwordForUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing *)error {
	return [self passwordForUsername:username service:service withOptions:nil error:error];
}

+ (NSString *)passwordForUsername:(NSString *)username service:(NSString *)service withOptions:(id<STSecurityKeychainReadingOptions>)options error:(NSError *__autoreleasing *)error {
	if (error) {
		*error = nil;
	}

	if (![username length] || ![service length]) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return nil;
	}

	NSMutableDictionary * const query = @{
		(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
		(__bridge id)kSecAttrService: service,
		(__bridge id)kSecAttrAccount: username,
		(__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
	}.mutableCopy;
#if defined(__IPHONE_8_0)
	if (&kSecUseOperationPrompt && options.prompt.length) {
		query[(__bridge id)kSecUseOperationPrompt] = options.prompt;
	}
#else
	if (error) {
		*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
	}
	return nil;
#endif

	CFDataRef result = NULL;
	OSStatus const err = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
	if (err != errSecSuccess) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
		}
		return nil;
	}
	NSData * const passwordData = (__bridge_transfer NSData *)result;
	return [[NSString alloc] initWithData:passwordData encoding:NSUTF8StringEncoding];
}


#pragma mark - Password - Deletion

+ (BOOL)deletePasswordForUsername:(NSString *)username service:(NSString *)service {
	return [self deletePasswordForUsername:username service:service withOptions:nil error:NULL];
}

+ (BOOL)deletePasswordForUsername:(NSString *)username service:(NSString *)service error:(NSError * __autoreleasing *)error {
	return [self deletePasswordForUsername:username service:service withOptions:nil error:error];
}

+ (BOOL)deletePasswordForUsername:(NSString *)username service:(NSString *)service withOptions:(id<STSecurityKeychainWritingOptions>)options error:(NSError *__autoreleasing *)error {
	if (error) {
		*error = nil;
	}

	if (![username length] || ![service length]) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return NO;
	}

	NSMutableDictionary * const query = @{
		(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
		(__bridge id)kSecAttrService: service,
		(__bridge id)kSecAttrAccount: username,
	}.mutableCopy;
#if defined(__IPHONE_8_0)
	if (&kSecUseOperationPrompt && options.prompt.length) {
		query[(__bridge id)kSecUseOperationPrompt] = options.prompt;
	}
#else
	if (error) {
		*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
	}
	return NO;
#endif

	OSStatus const err = SecItemDelete((__bridge CFDictionaryRef)query);
	if (err != errSecSuccess) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
		}
		return NO;
	}

	return YES;
}

+ (BOOL)deletePasswordsForService:(NSString *)service {
	return [self deletePasswordsForService:service withOptions:nil error:NULL];
}

+ (BOOL)deletePasswordsForService:(NSString *)service error:(NSError * __autoreleasing *)error {
	return [self deletePasswordsForService:service withOptions:nil error:error];
}

+ (BOOL)deletePasswordsForService:(NSString *)service withOptions:(id<STSecurityKeychainWritingOptions>)options error:(NSError *__autoreleasing *)error {
	if (error) {
		*error = nil;
	}

	if (![service length]) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return NO;
	}

	NSMutableDictionary * const query = @{
		(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
		(__bridge id)kSecAttrService: service,
	}.mutableCopy;
#if defined(__IPHONE_8_0)
	if (&kSecUseOperationPrompt && options.prompt.length) {
		query[(__bridge id)kSecUseOperationPrompt] = options.prompt;
	}
#else
	if (error) {
		*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
	}
	return NO;
#endif

	OSStatus const err = SecItemDelete((__bridge CFDictionaryRef)query);
	if (err != errSecSuccess) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
		}
		return NO;
	}

	return YES;
}


#pragma mark - RSA - Retrieval

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
		CFRelease(keyRef), keyRef = NULL;
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

		keyRef = (SecKeyRef)result;
	}

	STSecurityRSAPrivateKey *key = [[STSecurityRSAPrivateKey alloc] initWithKeyRef:keyRef];

	if (keyRef) {
		CFRelease(keyRef), keyRef = NULL;
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

#pragma mark - RSA - Deletion

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


#pragma mark - RSA - Generation

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
		CFRelease(publicKeyRef), publicKeyRef = NULL;
	}
	if (privateKeyRef) {
		CFRelease(privateKeyRef), privateKeyRef = NULL;
	}

	return YES;
}


#pragma mark - RSA - Importing

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
		CFRelease(publicKeyRef), publicKeyRef = NULL;
	}
	if (privateKeyRef) {
		CFRelease(privateKeyRef), privateKeyRef = NULL;
	}

	return YES;
}

@end
