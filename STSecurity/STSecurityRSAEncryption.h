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

#import <STSecurity/STSecurityRSAKey.h>

NS_ASSUME_NONNULL_BEGIN


typedef NS_ENUM(NSUInteger, STSecurityRSAPadding) {
	STSecurityRSAPaddingNone = 0,
	STSecurityRSAPaddingPKCS1,
	STSecurityRSAPaddingOAEP,
};


extern NSString * const STSecurityEncryptionErrorDomain;


@interface STSecurityRSAEncryption : NSObject

+ (NSData * __nullable)dataByEncryptingData:(NSData *)data withPublicKey:(STSecurityRSAPublicKey *)key padding:(enum STSecurityRSAPadding)padding NS_SWIFT_UNAVAILABLE("");
+ (NSData * __nullable)dataByEncryptingData:(NSData *)data withPublicKey:(STSecurityRSAPublicKey *)key padding:(enum STSecurityRSAPadding)padding error:(NSError * __autoreleasing __nullable * __nullable)error;

+ (NSData * __nullable)dataByDecryptingData:(NSData *)data withPrivateKey:(STSecurityRSAPrivateKey *)key padding:(enum STSecurityRSAPadding)padding NS_SWIFT_UNAVAILABLE("");
+ (NSData * __nullable)dataByDecryptingData:(NSData *)data withPrivateKey:(STSecurityRSAPrivateKey *)key padding:(enum STSecurityRSAPadding)padding error:(NSError * __autoreleasing __nullable * __nullable)error;

@end

NS_ASSUME_NONNULL_END
