//
//  STSecurityRSAKeyTests.m
//  STSecurity
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

@import XCTest;

#import <STSecurity/STSecurity.h>
#import "STSecurityRSAKey+Internal.h"


@interface STSecurityRSAKeyTests : XCTestCase
@end

@implementation STSecurityRSAKeyTests

- (void)testPublicKeyInstantiation {
	{
		STSecurityRSAPublicKey *key;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
#if defined(NS_BLOCK_ASSERTIONS)
		key = [[STSecurityRSAPublicKey alloc] initWithKeyRef:NULL keyData:nil];
#else
		XCTAssertThrows(key = [[STSecurityRSAPublicKey alloc] initWithKeyRef:NULL keyData:nil], @"Creating public key with neither keyRef nor data didn't throw");
#endif
#pragma clang diagnostic pop
		XCTAssertNil(key, @"Created public key with neither keyRef nor keyData");
	}
}

- (void)testPrivateKeyInstantiation {
	{
		STSecurityRSAPrivateKey *key;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
#if defined(NS_BLOCK_ASSERTIONS)
		key = [[STSecurityRSAPrivateKey alloc] initWithKeyRef:NULL];
#else
		XCTAssertThrows(key = [[STSecurityRSAPrivateKey alloc] initWithKeyRef:NULL], @"Creating private key with NULL keyRef");
#endif
#pragma clang diagnostic pop
		XCTAssertNil(key, @"Created private key with NULL keyRef");
	}
}

@end
