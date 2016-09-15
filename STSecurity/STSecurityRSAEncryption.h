//
//  STSecurityRSAEncryption.h
//  STSecurity
//
//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

@import Foundation;

#import "STSecurityRSAKey.h"


typedef NS_ENUM(NSUInteger, STSecurityRSAPadding) {
	STSecurityRSAPaddingNone = 0,
	STSecurityRSAPaddingPKCS1,
	STSecurityRSAPaddingOAEP,
};


extern NSString * const STSecurityEncryptionErrorDomain;


@interface STSecurityRSAEncryption : NSObject

+ (NSData *)dataByEncryptingData:(NSData *)data withPublicKey:(STSecurityRSAPublicKey *)key padding:(STSecurityRSAPadding)padding;
+ (NSData *)dataByEncryptingData:(NSData *)data withPublicKey:(STSecurityRSAPublicKey *)key padding:(STSecurityRSAPadding)padding error:(NSError * __autoreleasing *)error;

+ (NSData *)dataByDecryptingData:(NSData *)data withPrivateKey:(STSecurityRSAPrivateKey *)key padding:(STSecurityRSAPadding)padding;
+ (NSData *)dataByDecryptingData:(NSData *)data withPrivateKey:(STSecurityRSAPrivateKey *)key padding:(STSecurityRSAPadding)padding error:(NSError * __autoreleasing *)error;

@end
