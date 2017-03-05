//
//  STSecurityRSAKeyTests.m
//  STSecurity
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

@import XCTest;

#import "STSecurity.h"
#import "STSecurityRSAKey+Internal.h"


@interface STSecurityRSAKeyTests : XCTestCase
@end

@implementation STSecurityRSAKeyTests

- (void)testPublicKeyInstantiation {
	{
		STSecurityRSAPublicKey *key;
#if defined(NS_BLOCK_ASSERTIONS)
		key = [[STSecurityRSAPublicKey alloc] initWithKeyRef:NULL keyData:nil];
#else
		XCTAssertThrows(key = [[STSecurityRSAPublicKey alloc] initWithKeyRef:NULL keyData:nil], @"Creating public key with neither keyRef nor data didn't throw");
#endif
		XCTAssertNil(key, @"Created public key with neither keyRef nor keyData");
	}
}

- (void)testPrivateKeyInstantiation {
	{
		STSecurityRSAPrivateKey *key;
#if defined(NS_BLOCK_ASSERTIONS)
		key = [[STSecurityRSAPrivateKey alloc] initWithKeyRef:NULL];
#else
		XCTAssertThrows(key = [[STSecurityRSAPrivateKey alloc] initWithKeyRef:NULL], @"Creating private key with NULL keyRef");
#endif
		XCTAssertNil(key, @"Created private key with NULL keyRef");
	}
}

@end
