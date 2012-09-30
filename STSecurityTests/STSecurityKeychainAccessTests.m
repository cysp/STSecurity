//
//  STSecurityKeychainAccessTests.m
//  STSecurity
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import "STSecurityKeychainAccessTests.h"

#import "STSecurityKeychainAccess.h"


@implementation STSecurityKeychainAccessTests {
	STSecurityKeychainAccess *_keychainAccess;
}

- (void)setUp {
	_keychainAccess = [STSecurityKeychainAccess keychainAccess];
}

- (void)tearDown {
	_keychainAccess = nil;
}


- (void)testFetchNonexistent {
	{
		STSecurityPublicKey *key = [_keychainAccess fetchPublicKeyForTag:@"STSecurityTest.nonexistent"];
		STAssertNil(key, @"Keychain returned key for nonexistent tag");
	}
	{
		NSError *error = nil;
		STSecurityPublicKey *key = [_keychainAccess fetchPublicKeyForTag:@"STSecurityTest.nonexistent" error:&error];
		STAssertNil(key, @"Keychain returned key for nonexistent tag");
		STAssertNotNil(error, @"Keychain returned nil error");
	}
}

- (void)testDeleteNonexistent {
	{
		NSError *error = nil;
		BOOL status = [_keychainAccess deleteKeyForTag:@"STSecurityTest.nonexistent" error:&error];
		STAssertFalse(status, @"Keychain returned success deleting nonexistent key");
		STAssertNotNil(error, @"Keychain returned nil error");
		STAssertEquals(error.code, errSecItemNotFound, @"Keychain returned error.code not ItemNotFound: %d", error.code);
	}
}


- (void)_st_testGenerationOfSize:(NSUInteger)keySize {
	NSString * const publicKeyTag = @"STSecurityTest.testGeneration.public";
	NSString * const privateKeyTag = @"STSecurityTest.testGeneration.private";
	STSecurityPublicKey *publicKey = nil;
	STSecurityPrivateKey *privateKey = nil;

	{
		NSError *error = nil;
		BOOL status = [_keychainAccess generateRSAKeypairOfSize:keySize insertedIntoKeychainWithPublicKeyTag:publicKeyTag privateKeyTag:privateKeyTag publicKey:&publicKey privateKey:&privateKey error:&error];
		STAssertTrue(status, @"Keychain could not generate key pair");
		STAssertNil(error, @"Key generation returned error: %@", error);
	}
	STAssertNotNil(publicKey, @"Key generation resulted in no public key");
	STAssertNotNil(privateKey, @"Key generation resulted in no private key");

	{
		NSError *error = nil;
		BOOL status = [_keychainAccess deleteKeyForTag:publicKeyTag error:&error];
		STAssertTrue(status, @"Keychain could not delete public key");
		STAssertNil(error, @"Public key deletion returned error: %@", error);
	}
	{
		NSError *error = nil;
		BOOL status = [_keychainAccess deleteKeyForTag:privateKeyTag error:&error];
		STAssertTrue(status, @"Keychain could not delete private key");
		STAssertNil(error, @"Private key deletion returned error: %@", error);
	}
}

- (void)testGenerationSize384 { [self _st_testGenerationOfSize:384]; }
- (void)testGenerationSize512 { [self _st_testGenerationOfSize:512]; }
- (void)testGenerationSize768 { [self _st_testGenerationOfSize:768]; }
- (void)testGenerationSize1024 { [self _st_testGenerationOfSize:1024]; }
- (void)testGenerationSize1536 { [self _st_testGenerationOfSize:1536]; }
//- (void)testGenerationSize2048 { [self _st_testGenerationOfSize:2048]; }
//- (void)testGenerationSize3072 { [self _st_testGenerationOfSize:3072]; }
//- (void)testGenerationSize4096 { [self _st_testGenerationOfSize:4096]; }


- (void)testGenerationAnonymous {
	STSecurityPublicKey *publicKey = nil;
	STSecurityPrivateKey *privateKey = nil;

	{
		NSError *error = nil;
		BOOL status = [_keychainAccess generateRSAKeypairOfSize:1024 insertedIntoKeychainWithPublicKeyTag:nil privateKeyTag:nil publicKey:&publicKey privateKey:&privateKey error:&error];
		STAssertFalse(status, @"Keychain generated key pair without tags");
		STAssertNotNil(error, @"Key generation returned nil error");
	}
	STAssertNil(publicKey, @"Key generation resulted in no public key");
	STAssertNil(privateKey, @"Key generation resulted in no private key");
}

- (void)testGenerationAndFetch {
	NSString * const publicKeyTag = @"STSecurityTest.testGeneration.public";
	NSString * const privateKeyTag = @"STSecurityTest.testGeneration.private";
	STSecurityPublicKey *publicKey = nil;
	STSecurityPrivateKey *privateKey = nil;
	NSUInteger keySize = 1024;

	{
		NSError *error = nil;
		BOOL status = [_keychainAccess generateRSAKeypairOfSize:keySize insertedIntoKeychainWithPublicKeyTag:publicKeyTag privateKeyTag:privateKeyTag publicKey:&publicKey privateKey:&privateKey error:&error];
		STAssertTrue(status, @"Keychain could not generate key pair");
		STAssertNil(error, @"Key generation returned error: %@", error);
	}
	STAssertNotNil(publicKey, @"Key generation resulted in no public key");
	STAssertNotNil(privateKey, @"Key generation resulted in no private key");

	STSecurityPublicKey *fetchedPublicKey = nil;
	{
		NSError *error = nil;
		fetchedPublicKey = [_keychainAccess fetchPublicKeyForTag:publicKeyTag error:&error];
		STAssertNotNil(fetchedPublicKey, @"Keychain could not find public key");
		STAssertNil(error, @"Keychain fetch returned error: %@", error);
	}
	STAssertEqualObjects(publicKey.keyData, fetchedPublicKey.keyData, @"Fetched key doesn't equal original");

	{
		NSError *error = nil;
		BOOL status = [_keychainAccess deleteKeyForTag:publicKeyTag error:&error];
		STAssertTrue(status, @"Keychain could not delete public key");
		STAssertNil(error, @"Public key deletion returned error: %@", error);
	}
	{
		NSError *error = nil;
		BOOL status = [_keychainAccess deleteKeyForTag:privateKeyTag error:&error];
		STAssertTrue(status, @"Keychain could not delete private key");
		STAssertNil(error, @"Private key deletion returned error: %@", error);
	}
}

@end
