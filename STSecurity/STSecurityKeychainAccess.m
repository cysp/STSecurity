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

@import Security;

#import <STSecurity/STSecurity.h>

#import "STSecurityKeychainAccess+Internal.h"


NSString * const STSecurityKeychainAccessErrorDomain = @"STSecurityKeychainError";


@implementation STSecurityKeychainReadingOptions
- (instancetype)init {
	return [super init];
}
@synthesize prompt = _prompt;
@end

@implementation STSecurityKeychainWritingOptions
- (instancetype)init {
	return [super init];
}
@synthesize overwriteExisting = _overwriteExisting;
@synthesize accessibility = _accessibility;
@synthesize accessControl = _accessControl;
@synthesize prompt = _prompt;
@end


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
		NSDictionary *query = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			(__bridge id)kSecAttrService: service,
			(__bridge id)kSecAttrAccount: username,
			(__bridge id)kSecReturnAttributes: (__bridge id)kCFBooleanTrue,
			(__bridge id)kSecUseNoAuthenticationUI: (__bridge id)kCFBooleanTrue,
		};

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
		NSDictionary * const query = @{
			(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			(__bridge id)kSecAttrService: service,
			(__bridge id)kSecAttrAccount: username,
			(__bridge id)kSecReturnPersistentRef: (__bridge id)kCFBooleanTrue,
			(__bridge id)kSecUseNoAuthenticationUI: (__bridge id)kCFBooleanTrue,
		};

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
	CFTypeRef accessControlRef = SecAccessControlCreateWithFlags(NULL, accessibilityRef, (SecAccessControlCreateFlags)options.accessControl, NULL);
	if (!accessControlRef) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:errSecParam userInfo:nil];
		}
		return NO;
	}

	NSMutableDictionary * const attributes = @{
		(__bridge id)kSecValueData: passwordData,
	}.mutableCopy;
	if (accessControlRef) {
		attributes[(__bridge id)kSecAttrAccessControl] = (__bridge id)accessControlRef;
	} else {
		attributes[(__bridge id)kSecAttrAccessible] = (__bridge id)accessibilityRef;
	}

	if (accessControlRef) {
		CFRelease(accessControlRef);
		accessControlRef = NULL;
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
		if (options.prompt.length) {
			query[(__bridge id)kSecUseOperationPrompt] = options.prompt;
		}

		{
			OSStatus const err = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributes);
			if (err == errSecSuccess) {
				return YES;
			}
		}

		{
			OSStatus const err = SecItemDelete((__bridge CFDictionaryRef)query);
			if (err == errSecSuccess) {
			} else if (err == errSecItemNotFound) {
			} else {
				if (error) {
					*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
				}
				return NO;
			}
		}
	}

	if (options.prompt.length) {
		attributes[(__bridge id)kSecUseOperationPrompt] = options.prompt;
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
	if (options.prompt.length) {
		query[(__bridge id)kSecUseOperationPrompt] = options.prompt;
	}

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
	if (options.prompt.length) {
		query[(__bridge id)kSecUseOperationPrompt] = options.prompt;
	}

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
	if (options.prompt.length) {
		query[(__bridge id)kSecUseOperationPrompt] = options.prompt;
	}

	OSStatus const err = SecItemDelete((__bridge CFDictionaryRef)query);
	if (err != errSecSuccess) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityKeychainAccessErrorDomain code:err userInfo:nil];
		}
		return NO;
	}

	return YES;
}

@end
