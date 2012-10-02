//
//  STSecurityRSAKeyTests.m
//  STSecurity
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import "STSecurityRSAKeyTests.h"

#import "STSecurityRSAKey+Internal.h"


@implementation STSecurityRSAKeyTests

- (void)testPublicKeyInstantiation {
	{
		STSecurityRSAPublicKey *key;
#if NS_BLOCK_ASSERTIONS
		key = [[STSecurityRSAPublicKey alloc] initWithKeyRef:NULL keyData:nil];
#else
		STAssertThrows(key = [[STSecurityRSAPublicKey alloc] initWithKeyRef:NULL keyData:nil], @"Creating public key with neither keyRef nor data didn't throw");
#endif
		STAssertNil(key, @"Created public key with neither keyRef nor keyData");
	}
}

- (void)testPrivateKeyInstantiation {
	{
		STSecurityRSAPrivateKey *key;
#if NS_BLOCK_ASSERTIONS
		key = [[STSecurityRSAPrivateKey alloc] initWithKeyRef:NULL];
#else
		STAssertThrows(key = [[STSecurityRSAPrivateKey alloc] initWithKeyRef:NULL], @"Creating private key with NULL keyRef");
#endif
		STAssertNil(key, @"Created private key with NULL keyRef");
	}
}

@end
