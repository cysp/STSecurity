//
//  STSecurityKeyTests.m
//  STSecurity
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import "STSecurityKeyTests.h"

#import "STSecurityKey+Internal.h"


@implementation STSecurityKeyTests

- (void)testPublicKeyInstantiation {
	{
		STSecurityPublicKey *key;
#if NS_BLOCK_ASSERTIONS
		key = [[STSecurityPublicKey alloc] initWithKeyRef:NULL keyData:nil];
#else
		STAssertThrows(key = [[STSecurityPublicKey alloc] initWithKeyRef:NULL keyData:nil], @"Creating public key with neither keyRef nor data didn't throw");
#endif
		STAssertNil(key, @"Created public key with neither keyRef nor keyData");
	}
}

- (void)testPrivateKeyInstantiation {
	{
		STSecurityPrivateKey *key;
#if NS_BLOCK_ASSERTIONS
		key = [[STSecurityPrivateKey alloc] initWithKeyRef:NULL];
#else
		STAssertThrows(key = [[STSecurityPrivateKey alloc] initWithKeyRef:NULL], @"Creating private key with NULL keyRef");
#endif
		STAssertNil(key, @"Created private key with NULL keyRef");
	}
}

@end
