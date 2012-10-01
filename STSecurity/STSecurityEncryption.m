//
//  STSecurityEncryption.m
//  STSecurity
//
//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import "STSecurityEncryption.h"

#import "STSecurityKey+Internal.h"


NSString * const STSecurityEncryptionErrorDomain = @"STSecurityEncryption";


static inline SecPadding STSecurityPaddingToSecPadding(enum STSecurityPadding padding) {
	switch (padding) {
		case STSecurityPaddingNone:
			return kSecPaddingNone;
		case STSecurityPaddingPKCS1:
			return kSecPaddingPKCS1;
		case STSecurityPaddingOAEP:
			return kSecPaddingOAEP;
	}
	NSCAssert(0, @"STSecurityPadding unknown value: %u", padding);
	return kSecPaddingNone;
}


@implementation STSecurityEncryption

#pragma mark - Encryption

+ (NSData *)dataByEncryptingData:(NSData *)data withPublicKey:(STSecurityPublicKey *)key padding:(enum STSecurityPadding)padding {
	return [self dataByEncryptingData:data withPublicKey:key padding:padding error:nil];
}
+ (NSData *)dataByEncryptingData:(NSData *)data withPublicKey:(STSecurityPublicKey *)key padding:(enum STSecurityPadding)padding error:(NSError * __autoreleasing *)error {
	NSParameterAssert(key);
	if (!key) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityEncryptionErrorDomain code:0 userInfo:nil];
		}
		return nil;
	}
	if (!data) {
		return nil;
	}

	size_t plainTextLen = [data length];
	const uint8_t *plainTextBytes = [data bytes];

	NSUInteger blockSize = [key blockSize];
	NSUInteger cipherTextBlocks = (plainTextLen + blockSize - 1) / blockSize;
	size_t cipherTextLen = cipherTextBlocks * blockSize;
	uint8_t *cipherText = calloc(1, cipherTextLen);

	OSStatus err = SecKeyEncrypt(key.keyRef, STSecurityPaddingToSecPadding(padding), plainTextBytes, plainTextLen, cipherText, &cipherTextLen);
	if (err != errSecSuccess) {
		free(cipherText), cipherText = nil;
		if (error) {
			*error = [NSError errorWithDomain:STSecurityEncryptionErrorDomain code:err userInfo:nil];
		}
		return nil;
	}

	return [[NSData alloc] initWithBytesNoCopy:cipherText length:cipherTextLen freeWhenDone:YES];
}


#pragma mark - Decryption

+ (NSData *)dataByDecryptingData:(NSData *)data withPrivateKey:(STSecurityPrivateKey *)key padding:(enum STSecurityPadding)padding {
	return [self dataByDecryptingData:data withPrivateKey:key padding:padding error:nil];
}

+ (NSData *)dataByDecryptingData:(NSData *)data withPrivateKey:(STSecurityPrivateKey *)key padding:(enum STSecurityPadding)padding error:(NSError *__autoreleasing *)error {
	NSParameterAssert(key);
	if (!key) {
		if (error) {
			*error = [NSError errorWithDomain:STSecurityEncryptionErrorDomain code:0 userInfo:nil];
		}
		return nil;
	}
	if (!data) {
		return nil;
	}

	size_t cipherTextLen = [data length];
	const uint8_t *cipherTextBytes = [data bytes];

	NSUInteger blockSize = [key blockSize];
	NSUInteger plainTextBlocks = (cipherTextLen + blockSize - 1) / blockSize;
	size_t plainTextLen = plainTextBlocks * blockSize;
	uint8_t *plainText = calloc(1, plainTextLen);

	OSStatus err = SecKeyDecrypt(key.keyRef, STSecurityPaddingToSecPadding(padding), cipherTextBytes, cipherTextLen, plainText, &plainTextLen);
	if (err != errSecSuccess) {
		free(plainText), plainText = NULL;
		if (error) {
			*error = [NSError errorWithDomain:STSecurityEncryptionErrorDomain code:err userInfo:nil];
		}
		return nil;
	}

	return [[NSData alloc] initWithBytesNoCopy:plainText length:plainTextLen freeWhenDone:YES];
}

@end
