//
//  STSecurityEncryptionTests.m
//  STSecurity
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import "STSecurityEncryptionTests.h"

#import "STSecurityKeychainAccess.h"
#import "STSecurityEncryption.h"
#import "STSecurityRandomization.h"


@implementation STSecurityEncryptionTests

- (void)_st_testEncryptionRoundtripWithData:(NSData *)data keySize:(NSUInteger)keySize padding:(enum STSecurityPadding)padding {
	NSString * const publicKeyTag = @"STSecurityTest.testEncryption.public";
	NSString * const privateKeyTag = @"STSecurityTest.testEncryption.private";
	STSecurityPublicKey *publicKey = nil;
	STSecurityPrivateKey *privateKey = nil;

	{
		NSError *error = nil;
		BOOL status = [STSecurityKeychainAccess generateRSAKeypairOfSize:keySize insertedIntoKeychainWithPublicKeyTag:publicKeyTag privateKeyTag:privateKeyTag publicKey:&publicKey privateKey:&privateKey error:&error];
		STAssertTrue(status, @"Keychain could not generate key pair");
		STAssertNil(error, @"Key generation returned error: %@", error);
	}
	STAssertNotNil(publicKey, @"Key generation resulted in no public key");
	STAssertNotNil(privateKey, @"Key generation resulted in no private key");

	NSData *dataEncrypted = nil;
	{
		NSError *error = nil;
		dataEncrypted = [STSecurityEncryption dataByEncryptingData:data withPublicKey:publicKey padding:padding error:&error];
		STAssertNotNil(dataEncrypted, @"Encryption returned nil data");
		STAssertNil(error, @"Encryption returned error: %@", error);
	}
	STAssertFalse([data isEqualToData:dataEncrypted], @"Encrypted data isEqual: initial");

	NSData *dataDecrypted = nil;
	{
		NSError *error = nil;
		dataDecrypted = [STSecurityEncryption dataByDecryptingData:dataEncrypted withPrivateKey:privateKey padding:padding error:&error];
		STAssertNotNil(dataDecrypted, @"Decryption returned nil data");
		STAssertNil(error, @"Decryption returned error: %@", error);
	}
	STAssertEqualObjects(data, dataDecrypted, @"Decrypted data doesn't match input");

	{
		NSError *error = nil;
		BOOL status = [STSecurityKeychainAccess deleteKeyForTag:publicKeyTag error:&error];
		STAssertTrue(status, @"Keychain could not delete public key");
		STAssertNil(error, @"Public key deletion returned error: %@", error);
	}
	{
		NSError *error = nil;
		BOOL status = [STSecurityKeychainAccess deleteKeyForTag:privateKeyTag error:&error];
		STAssertTrue(status, @"Keychain could not delete private key");
		STAssertNil(error, @"Private key deletion returned error: %@", error);
	}
}

- (void)testEncryptionRoundtrip0 {
	[self _st_testEncryptionRoundtripWithData:[@"plaintext" dataUsingEncoding:NSUTF8StringEncoding] keySize:1024 padding:STSecurityPaddingPKCS1];
}

- (void)testEncryptionRoundtrip1 {
	NSData *randomData = [STSecurityRandomization dataWithRandomBytesOfLength:16];
	NSMutableData *data = [NSMutableData dataWithCapacity:128];
	while ([data length] < 128) {
		[data appendData:randomData];
	}
	[data setLength:128];
	[self _st_testEncryptionRoundtripWithData:data keySize:1024 padding:STSecurityPaddingNone];
}

- (void)testEncryptionRoundtrip2 {
	NSData *randomData = [STSecurityRandomization dataWithRandomBytesOfLength:16];
	NSMutableData *data = [NSMutableData dataWithCapacity:128];
	for (int i = 0; i < 8; ++i) {
		[data appendData:randomData];
	}
	[data setLength:128 - 11];
	[self _st_testEncryptionRoundtripWithData:data keySize:1024 padding:STSecurityPaddingPKCS1];
}

@end
