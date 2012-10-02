//
//  STSecurityRSAEncryption.m
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


#import "STSecurityRSAEncryption.h"

#import "STSecurityRSAKey+Internal.h"


NSString * const STSecurityEncryptionErrorDomain = @"STSecurityEncryption";


static inline SecPadding STSecurityRSAPaddingToSecPadding(enum STSecurityRSAPadding padding) {
	switch (padding) {
		case STSecurityRSAPaddingNone:
			return kSecPaddingNone;
		case STSecurityRSAPaddingPKCS1:
			return kSecPaddingPKCS1;
		case STSecurityRSAPaddingOAEP:
			return kSecPaddingOAEP;
	}
	NSCAssert(0, @"STSecurityPadding unknown value: %u", padding);
	return kSecPaddingNone;
}


@implementation STSecurityRSAEncryption

#pragma mark - Encryption

+ (NSData *)dataByEncryptingData:(NSData *)data withPublicKey:(STSecurityRSAPublicKey *)key padding:(enum STSecurityRSAPadding)padding {
	return [self dataByEncryptingData:data withPublicKey:key padding:padding error:nil];
}
+ (NSData *)dataByEncryptingData:(NSData *)data withPublicKey:(STSecurityRSAPublicKey *)key padding:(enum STSecurityRSAPadding)padding error:(NSError * __autoreleasing *)error {
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

	size_t cipherTextLen = [key blockSize];
	uint8_t *cipherText = calloc(1, cipherTextLen);

	OSStatus err = SecKeyEncrypt(key.keyRef, STSecurityRSAPaddingToSecPadding(padding), plainTextBytes, plainTextLen, cipherText, &cipherTextLen);
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

+ (NSData *)dataByDecryptingData:(NSData *)data withPrivateKey:(STSecurityRSAPrivateKey *)key padding:(enum STSecurityRSAPadding)padding {
	return [self dataByDecryptingData:data withPrivateKey:key padding:padding error:nil];
}

+ (NSData *)dataByDecryptingData:(NSData *)data withPrivateKey:(STSecurityRSAPrivateKey *)key padding:(enum STSecurityRSAPadding)padding error:(NSError *__autoreleasing *)error {
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

	size_t plainTextLen = [key blockSize];
	uint8_t *plainText = calloc(1, plainTextLen);

	OSStatus err = SecKeyDecrypt(key.keyRef, STSecurityRSAPaddingToSecPadding(padding), cipherTextBytes, cipherTextLen, plainText, &plainTextLen);
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
