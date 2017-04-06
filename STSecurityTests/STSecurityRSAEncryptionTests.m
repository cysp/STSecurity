//
//  STSecurityRSAEncryptionTests.m
//  STSecurity
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

@import XCTest;

#import "STSecurity.h"


@interface STSecurityRSAEncryptionTests : XCTestCase
@end

@implementation STSecurityRSAEncryptionTests

#if !defined(TRAVIS) || !(TRAVIS + 0)

- (void)testEncryptionInvalid {
	NSString * const keyTag = @"STSecurityTest.testEncryptionInvalid";
	STSecurityRSAPublicKey *publicKey = nil;
	STSecurityRSAPrivateKey *privateKey = nil;
	NSUInteger keySize = 512;

	[STSecurityKeychainAccess deleteRSAKeysForTag:keyTag error:NULL];

	{
		NSError *error = nil;
		BOOL status = [STSecurityKeychainAccess generateRSAKeypairOfSize:keySize insertedIntoKeychainWithTag:keyTag publicKey:&publicKey privateKey:&privateKey error:&error];
		XCTAssertTrue(status, @"Keychain could not generate key pair");
		XCTAssertNil(error, @"Key generation returned error: %@", error);
	}
	XCTAssertNotNil(publicKey, @"Key generation resulted in no public key");
	XCTAssertNotNil(privateKey, @"Key generation resulted in no private key");

	{
		NSError *error = nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
		NSData *data = [STSecurityRSAEncryption dataByEncryptingData:nil withPublicKey:publicKey padding:STSecurityRSAPaddingPKCS1 error:&error];
#pragma clang diagnostic pop
		XCTAssertNil(data);
		XCTAssertNotNil(error);
	}

	{
		NSError *error = nil;
		NSData *data = [STSecurityRSAEncryption dataByEncryptingData:[NSData data] withPublicKey:publicKey padding:STSecurityRSAPaddingPKCS1 error:&error];
		XCTAssertNotNil(data);
		XCTAssertNil(error);
	}

	{
		NSError *error = nil;
		BOOL status = [STSecurityKeychainAccess deleteRSAKeysForTag:keyTag error:&error];
		XCTAssertTrue(status, @"Keychain could not delete public key");
		XCTAssertNil(error, @"Public key deletion returned error: %@", error);
	}
}

- (void)_st_testEncryptionRoundtripWithData:(NSData *)data keySize:(NSUInteger)keySize padding:(enum STSecurityRSAPadding)padding {
	NSString * const keyTag = @"STSecurityTest.testEncryption";
	STSecurityRSAPublicKey *publicKey = nil;
	STSecurityRSAPrivateKey *privateKey = nil;

	{
		NSError *error = nil;
		BOOL status = [STSecurityKeychainAccess generateRSAKeypairOfSize:keySize insertedIntoKeychainWithTag:keyTag publicKey:&publicKey privateKey:&privateKey error:&error];
		XCTAssertTrue(status, @"Keychain could not generate key pair");
		XCTAssertNil(error, @"Key generation returned error: %@", error);
	}
	XCTAssertNotNil(publicKey, @"Key generation resulted in no public key");
	XCTAssertNotNil(privateKey, @"Key generation resulted in no private key");

	NSData *dataEncrypted = nil;
	{
		NSError *error = nil;
		dataEncrypted = [STSecurityRSAEncryption dataByEncryptingData:data withPublicKey:publicKey padding:padding error:&error];
		XCTAssertNotNil(dataEncrypted, @"Encryption returned nil data");
		XCTAssertNil(error, @"Encryption returned error: %@", error);
	}
	XCTAssertFalse([data isEqualToData:dataEncrypted], @"Encrypted data isEqual: initial");

	NSData *dataDecrypted = nil;
	{
		NSError *error = nil;
		dataDecrypted = [STSecurityRSAEncryption dataByDecryptingData:dataEncrypted withPrivateKey:privateKey padding:padding error:&error];
		XCTAssertNotNil(dataDecrypted, @"Decryption returned nil data");
		XCTAssertNil(error, @"Decryption returned error: %@", error);
	}
	XCTAssertEqualObjects(data, dataDecrypted, @"Decrypted data doesn't match input");

	{
		NSError *error = nil;
		BOOL status = [STSecurityKeychainAccess deleteRSAKeysForTag:keyTag error:&error];
		XCTAssertTrue(status, @"Keychain could not delete public key");
		XCTAssertNil(error, @"Public key deletion returned error: %@", error);
	}
}

- (void)testEncryptionRoundtrip0 {
	[self _st_testEncryptionRoundtripWithData:[@"plaintext" dataUsingEncoding:NSUTF8StringEncoding] keySize:1024 padding:STSecurityRSAPaddingPKCS1];
}

- (void)testEncryptionRoundtrip1 {
	NSData *randomData = [STSecurityRandomization dataWithRandomBytesOfLength:16];
	NSMutableData *data = [NSMutableData dataWithCapacity:128];
	while ([data length] < 128) {
		[data appendData:randomData];
	}
	[data setLength:128 - 11];
	[self _st_testEncryptionRoundtripWithData:data keySize:1024 padding:STSecurityRSAPaddingPKCS1];
}

- (void)testEncryptionRoundtrip2 {
	NSData *randomData = [STSecurityRandomization dataWithRandomBytesOfLength:16];
	NSMutableData *data = [NSMutableData dataWithCapacity:64];
	for (int i = 0; i < 4; ++i) {
		[data appendData:randomData];
	}
	[data setLength:64];
	[self _st_testEncryptionRoundtripWithData:data keySize:1024 padding:STSecurityRSAPaddingOAEP];
}
#endif

- (void)testEncryptionInserted {
	NSString * const keyTag = @"STSecurityTest.testInsertion";
	STSecurityRSAPublicKey *publicKey = nil;
	STSecurityRSAPrivateKey *privateKey = nil;

	unsigned char const pub_bytes[] = {
		0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
		0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
		0x00, 0xb6, 0x63, 0x51, 0x02, 0xee, 0xd9, 0x71, 0x5e, 0x2e, 0x88, 0x6a, 0x61, 0xd1, 0x6a, 0x22,
		0xb6, 0x7d, 0x3e, 0xae, 0xb3, 0xf1, 0x2c, 0x7f, 0xa7, 0xb3, 0xd7, 0xe1, 0x1e, 0x25, 0x41, 0x38,
		0xc4, 0xab, 0xef, 0x43, 0xd8, 0x93, 0x55, 0xff, 0x42, 0x89, 0xda, 0x54, 0x46, 0x8b, 0xce, 0x54,
		0x06, 0x28, 0x9d, 0xae, 0x42, 0x12, 0xf3, 0x3f, 0x26, 0x70, 0x31, 0x03, 0x6f, 0xa5, 0x61, 0x08,
		0x48, 0x73, 0xd7, 0xdf, 0x74, 0x65, 0x01, 0xec, 0xb8, 0x48, 0x11, 0xdf, 0x45, 0x8d, 0x2c, 0x98,
		0x08, 0xd9, 0x49, 0xbd, 0xfb, 0x71, 0x52, 0x21, 0xd6, 0x15, 0x84, 0xf8, 0xde, 0xfa, 0xcc, 0xdd,
		0x12, 0xbc, 0xad, 0xd5, 0x7e, 0xac, 0x7b, 0x6e, 0xcf, 0x52, 0xdb, 0xf6, 0x6e, 0x22, 0x65, 0xd0,
		0xa5, 0xfd, 0x39, 0xc6, 0xbc, 0xbb, 0x4a, 0x3a, 0x55, 0xfd, 0xd5, 0x2a, 0xe7, 0xee, 0x7e, 0xaf,
		0x6f, 0xc3, 0x7c, 0x8b, 0x0e, 0x6c, 0xb4, 0xfb, 0x51, 0xb9, 0x22, 0xa1, 0x4a, 0xb0, 0x6d, 0x21,
		0x6d, 0xe4, 0xc4, 0x9c, 0x72, 0x26, 0xe7, 0xef, 0x76, 0xa6, 0xaf, 0x84, 0x5e, 0xff, 0x4a, 0x90,
		0x93, 0x49, 0xfb, 0x4c, 0xee, 0xdc, 0x87, 0x5f, 0x9a, 0xfa, 0x8b, 0x07, 0xaa, 0x96, 0x5c, 0xe9,
		0x34, 0x51, 0x5e, 0x8c, 0x14, 0xc5, 0x48, 0x1e, 0x42, 0x7d, 0x10, 0xfb, 0xbd, 0x62, 0x4a, 0xfc,
		0x96, 0x57, 0xea, 0x4c, 0x0c, 0x7d, 0xd1, 0x18, 0x3e, 0xd2, 0xea, 0xd7, 0x0d, 0xad, 0x5d, 0xfd,
		0x3a, 0xc6, 0xb9, 0xed, 0x78, 0x22, 0xf3, 0x7f, 0x69, 0xe6, 0xb8, 0x0c, 0x09, 0xe4, 0xf0, 0x7f,
		0x8a, 0xc6, 0x1b, 0xe3, 0x63, 0xae, 0x57, 0xe7, 0x6c, 0xe7, 0x92, 0xb7, 0x7b, 0xab, 0x74, 0xdb,
		0x1f, 0x69, 0x3c, 0x45, 0x41, 0x8d, 0x29, 0xd0, 0xda, 0xe7, 0x99, 0xd4, 0xc7, 0x40, 0x58, 0xce,
		0x23, 0x02, 0x03, 0x01, 0x00, 0x01
	};
	unsigned int const pub_bytes_len = 294;

	unsigned char const prv_bytes[] = {
		0x30, 0x82, 0x04, 0xa5, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb6, 0x63, 0x51, 0x02,
		0xee, 0xd9, 0x71, 0x5e, 0x2e, 0x88, 0x6a, 0x61, 0xd1, 0x6a, 0x22, 0xb6, 0x7d, 0x3e, 0xae, 0xb3,
		0xf1, 0x2c, 0x7f, 0xa7, 0xb3, 0xd7, 0xe1, 0x1e, 0x25, 0x41, 0x38, 0xc4, 0xab, 0xef, 0x43, 0xd8,
		0x93, 0x55, 0xff, 0x42, 0x89, 0xda, 0x54, 0x46, 0x8b, 0xce, 0x54, 0x06, 0x28, 0x9d, 0xae, 0x42,
		0x12, 0xf3, 0x3f, 0x26, 0x70, 0x31, 0x03, 0x6f, 0xa5, 0x61, 0x08, 0x48, 0x73, 0xd7, 0xdf, 0x74,
		0x65, 0x01, 0xec, 0xb8, 0x48, 0x11, 0xdf, 0x45, 0x8d, 0x2c, 0x98, 0x08, 0xd9, 0x49, 0xbd, 0xfb,
		0x71, 0x52, 0x21, 0xd6, 0x15, 0x84, 0xf8, 0xde, 0xfa, 0xcc, 0xdd, 0x12, 0xbc, 0xad, 0xd5, 0x7e,
		0xac, 0x7b, 0x6e, 0xcf, 0x52, 0xdb, 0xf6, 0x6e, 0x22, 0x65, 0xd0, 0xa5, 0xfd, 0x39, 0xc6, 0xbc,
		0xbb, 0x4a, 0x3a, 0x55, 0xfd, 0xd5, 0x2a, 0xe7, 0xee, 0x7e, 0xaf, 0x6f, 0xc3, 0x7c, 0x8b, 0x0e,
		0x6c, 0xb4, 0xfb, 0x51, 0xb9, 0x22, 0xa1, 0x4a, 0xb0, 0x6d, 0x21, 0x6d, 0xe4, 0xc4, 0x9c, 0x72,
		0x26, 0xe7, 0xef, 0x76, 0xa6, 0xaf, 0x84, 0x5e, 0xff, 0x4a, 0x90, 0x93, 0x49, 0xfb, 0x4c, 0xee,
		0xdc, 0x87, 0x5f, 0x9a, 0xfa, 0x8b, 0x07, 0xaa, 0x96, 0x5c, 0xe9, 0x34, 0x51, 0x5e, 0x8c, 0x14,
		0xc5, 0x48, 0x1e, 0x42, 0x7d, 0x10, 0xfb, 0xbd, 0x62, 0x4a, 0xfc, 0x96, 0x57, 0xea, 0x4c, 0x0c,
		0x7d, 0xd1, 0x18, 0x3e, 0xd2, 0xea, 0xd7, 0x0d, 0xad, 0x5d, 0xfd, 0x3a, 0xc6, 0xb9, 0xed, 0x78,
		0x22, 0xf3, 0x7f, 0x69, 0xe6, 0xb8, 0x0c, 0x09, 0xe4, 0xf0, 0x7f, 0x8a, 0xc6, 0x1b, 0xe3, 0x63,
		0xae, 0x57, 0xe7, 0x6c, 0xe7, 0x92, 0xb7, 0x7b, 0xab, 0x74, 0xdb, 0x1f, 0x69, 0x3c, 0x45, 0x41,
		0x8d, 0x29, 0xd0, 0xda, 0xe7, 0x99, 0xd4, 0xc7, 0x40, 0x58, 0xce, 0x23, 0x02, 0x03, 0x01, 0x00,
		0x01, 0x02, 0x82, 0x01, 0x00, 0x08, 0xce, 0x2a, 0xaf, 0x15, 0x90, 0xf1, 0xe4, 0x36, 0x22, 0xe7,
		0xdf, 0xe9, 0x18, 0x52, 0xac, 0xb4, 0xc7, 0x3d, 0xef, 0xfa, 0x08, 0xc7, 0xf0, 0xf4, 0xc1, 0xcb,
		0x60, 0x85, 0x33, 0xec, 0xe5, 0xb1, 0xd7, 0x4f, 0x53, 0x39, 0x69, 0xc1, 0x75, 0x18, 0xea, 0xad,
		0x7e, 0xea, 0x68, 0xff, 0xad, 0x7c, 0x70, 0x80, 0x65, 0x38, 0x3c, 0xfe, 0x23, 0x80, 0xef, 0x1c,
		0xd7, 0x5b, 0x08, 0xa0, 0x39, 0xbf, 0x3e, 0x00, 0xcf, 0xc1, 0xc0, 0xa2, 0x09, 0x13, 0x91, 0xa9,
		0x51, 0xd6, 0x4a, 0xfc, 0xdc, 0x10, 0x81, 0x7a, 0xe6, 0x94, 0xc5, 0xfe, 0x54, 0x33, 0x9d, 0xc3,
		0xd6, 0x20, 0x0d, 0x9b, 0xee, 0xb7, 0xa5, 0x3c, 0xd5, 0x6c, 0xc6, 0x58, 0xc7, 0x31, 0x9c, 0xe4,
		0xfc, 0xd4, 0x34, 0x4e, 0x2a, 0x75, 0x5b, 0x40, 0xb9, 0x03, 0xe1, 0xc5, 0x87, 0x39, 0x45, 0xfd,
		0x58, 0x4d, 0x2f, 0x58, 0x90, 0xdb, 0xdf, 0x00, 0x3e, 0xc2, 0xc5, 0x0b, 0x80, 0x7e, 0xbb, 0xbc,
		0xdc, 0xbd, 0x6d, 0xcc, 0x20, 0x89, 0x74, 0xb9, 0x4d, 0x4a, 0xb4, 0xe0, 0x9a, 0x61, 0xf0, 0xa7,
		0x58, 0xe5, 0x3d, 0xf4, 0x65, 0x8a, 0xb5, 0x3d, 0xe7, 0x61, 0x57, 0x89, 0x8f, 0x39, 0x89, 0xf9,
		0x4f, 0xc4, 0xb0, 0xcf, 0x80, 0x71, 0x72, 0x79, 0x82, 0x95, 0x02, 0xf0, 0xa4, 0xc4, 0xed, 0xd0,
		0x0e, 0xb5, 0xf4, 0xc4, 0x31, 0x6d, 0x5d, 0xe9, 0xf9, 0x1b, 0x55, 0x4f, 0x42, 0x9d, 0x8a, 0x0d,
		0xc4, 0x9c, 0x8a, 0x0c, 0xa8, 0x69, 0x1a, 0xf8, 0xb6, 0x73, 0xc5, 0x64, 0x2c, 0xa3, 0xd9, 0x59,
		0x0c, 0x2e, 0x7a, 0x6c, 0x6b, 0xf3, 0xea, 0xd7, 0xb6, 0x4a, 0xcd, 0xdd, 0x82, 0xd5, 0x64, 0x35,
		0x8d, 0x8c, 0xa4, 0x89, 0x41, 0x04, 0x98, 0x3a, 0x35, 0x90, 0x09, 0x45, 0x3d, 0x25, 0xdf, 0xd6,
		0x55, 0xe0, 0x68, 0x21, 0xa1, 0x02, 0x81, 0x81, 0x00, 0xe3, 0x66, 0x03, 0x23, 0xf1, 0xba, 0x2e,
		0x99, 0xbd, 0x99, 0x0f, 0x7f, 0xc4, 0x6d, 0xf9, 0x66, 0xb9, 0x7f, 0x23, 0x91, 0x8a, 0x73, 0x0b,
		0x65, 0x63, 0xd7, 0xe9, 0xf5, 0x86, 0x72, 0x8f, 0x9b, 0xc4, 0x48, 0x80, 0x1c, 0xd7, 0xae, 0x06,
		0xa4, 0x58, 0x5c, 0x13, 0x7d, 0x47, 0xb1, 0x30, 0xc0, 0xb9, 0x51, 0xa2, 0x92, 0x72, 0x02, 0xdf,
		0xd8, 0xae, 0x3c, 0xff, 0xa7, 0x1c, 0x7b, 0xb3, 0x1f, 0x68, 0xf1, 0x20, 0xd3, 0x36, 0xbe, 0xa3,
		0x1f, 0x26, 0x43, 0x62, 0x4e, 0x3d, 0xc8, 0xde, 0x87, 0x41, 0x3b, 0x4e, 0x60, 0x30, 0xc2, 0x9b,
		0xda, 0xd6, 0xf1, 0xe6, 0xda, 0xa9, 0x85, 0xd4, 0x47, 0xa8, 0xe3, 0x51, 0x99, 0x85, 0x77, 0xd9,
		0x70, 0x09, 0xfd, 0x0b, 0x88, 0x20, 0xac, 0x1f, 0x2f, 0x19, 0xf8, 0x47, 0x31, 0xa7, 0xf7, 0x73,
		0xa0, 0x41, 0x4b, 0xfd, 0x6d, 0xe2, 0xc0, 0xef, 0x65, 0x02, 0x81, 0x81, 0x00, 0xcd, 0x54, 0x03,
		0x67, 0x7c, 0x4a, 0x3b, 0x47, 0x7f, 0x90, 0x66, 0x0f, 0xfe, 0xe2, 0xdf, 0xaa, 0xcd, 0xa3, 0x1a,
		0xdb, 0xc1, 0x7f, 0xf3, 0x56, 0xa3, 0x5d, 0x7c, 0x82, 0xfd, 0xf4, 0x07, 0x28, 0x24, 0x0e, 0xaa,
		0x23, 0xf6, 0x0c, 0x92, 0x59, 0x17, 0xe4, 0x49, 0x27, 0x51, 0xdc, 0x40, 0x47, 0x80, 0x83, 0x20,
		0x1e, 0x70, 0x99, 0x41, 0xac, 0x59, 0xc8, 0xe6, 0xaf, 0x31, 0x23, 0x95, 0x57, 0xbc, 0xdc, 0xbd,
		0xe9, 0x8e, 0x66, 0xb7, 0xcc, 0xc1, 0xf5, 0xd5, 0x4d, 0x01, 0x01, 0x71, 0x5a, 0xb3, 0x80, 0x6a,
		0x8c, 0x6a, 0xeb, 0xf5, 0x31, 0xd9, 0xe3, 0x86, 0x27, 0x2d, 0xef, 0xc6, 0x41, 0x77, 0xf0, 0x1a,
		0x99, 0x16, 0x17, 0x5f, 0x2a, 0x43, 0x9b, 0xe8, 0x01, 0x9a, 0xcc, 0x24, 0x06, 0x7d, 0xc4, 0xe5,
		0xf7, 0xc3, 0xa1, 0xea, 0xc9, 0xc5, 0x4b, 0x3c, 0x2f, 0xb7, 0xba, 0x02, 0xe7, 0x02, 0x81, 0x81,
		0x00, 0xa9, 0x3b, 0x31, 0x19, 0x1d, 0xfb, 0xa6, 0x54, 0xaa, 0x42, 0x6f, 0xc3, 0x71, 0x67, 0x3a,
		0xd5, 0x95, 0x35, 0x26, 0x3e, 0x59, 0x1f, 0xf7, 0x1a, 0x34, 0xac, 0xea, 0x23, 0xdc, 0x34, 0x03,
		0xe6, 0x33, 0xb4, 0x95, 0x0b, 0x62, 0x03, 0xd4, 0x53, 0x98, 0xa2, 0xa5, 0xaa, 0x75, 0xa1, 0x4b,
		0x9c, 0x12, 0x0e, 0xcc, 0x03, 0x5a, 0xb0, 0x02, 0xf1, 0x19, 0xf2, 0xb1, 0x7c, 0x27, 0x79, 0x73,
		0xbb, 0xeb, 0x78, 0x90, 0x2a, 0x40, 0x32, 0xad, 0xe9, 0x2f, 0xab, 0xb4, 0x4c, 0x70, 0x34, 0xbe,
		0x4f, 0x40, 0x5f, 0xa7, 0x9b, 0x74, 0x8e, 0x50, 0x39, 0x14, 0x00, 0x21, 0x03, 0x18, 0x68, 0x4d,
		0xac, 0x2a, 0xe7, 0x49, 0xc2, 0x0c, 0x0f, 0x3e, 0x95, 0xe0, 0x09, 0x1e, 0xfc, 0xe6, 0xfb, 0xd1,
		0x95, 0x57, 0x29, 0x6b, 0xaa, 0x6b, 0xcb, 0x7f, 0x94, 0x83, 0x23, 0xcf, 0x6e, 0x68, 0xf3, 0x96,
		0xf5, 0x02, 0x81, 0x81, 0x00, 0xb6, 0xa5, 0x2a, 0x16, 0x0e, 0xe8, 0x95, 0x4c, 0xa7, 0x7b, 0x92,
		0x5e, 0x5e, 0x34, 0x00, 0x14, 0x16, 0xb2, 0x24, 0xfd, 0x20, 0x66, 0x29, 0xd6, 0x82, 0xa1, 0x71,
		0x55, 0xb0, 0x83, 0x37, 0x2e, 0x8c, 0xcc, 0x82, 0xaa, 0x54, 0x7f, 0xa0, 0x5b, 0x22, 0x36, 0x8e,
		0xa0, 0x2c, 0x60, 0x48, 0xc9, 0x91, 0xd6, 0x92, 0x66, 0xa1, 0x70, 0xa2, 0x8b, 0xa6, 0x9e, 0x60,
		0x1d, 0xad, 0x0f, 0x63, 0x14, 0x55, 0xca, 0xe2, 0x20, 0x74, 0xec, 0x88, 0x48, 0xda, 0xac, 0x4c,
		0x1e, 0x20, 0x6b, 0xe1, 0x22, 0x76, 0x94, 0x1f, 0xb3, 0x62, 0x95, 0x1c, 0x5a, 0x48, 0xe0, 0xec,
		0x7f, 0xc3, 0x8c, 0x0b, 0x86, 0x47, 0x23, 0x4c, 0xf5, 0xaa, 0x42, 0x06, 0x04, 0x39, 0x79, 0xe0,
		0xea, 0x34, 0x81, 0xac, 0xf6, 0x1d, 0x40, 0x5d, 0xf4, 0x84, 0x90, 0x6e, 0xa3, 0x27, 0x1e, 0x22,
		0x9e, 0xab, 0xc7, 0x0a, 0x37, 0x02, 0x81, 0x81, 0x00, 0x85, 0xee, 0x09, 0x5e, 0x36, 0x6f, 0x0f,
		0x95, 0x03, 0x80, 0x3e, 0x08, 0xa4, 0x8a, 0x91, 0x06, 0xb3, 0xff, 0x79, 0x06, 0x31, 0x5b, 0x18,
		0xeb, 0xfd, 0x2f, 0xa9, 0x0d, 0x19, 0x9d, 0xc4, 0xf0, 0x02, 0xf7, 0x4d, 0x77, 0x23, 0xd7, 0x68,
		0xbf, 0xef, 0x15, 0x43, 0x33, 0xa1, 0x79, 0x7f, 0xc5, 0xc1, 0xfd, 0xc7, 0xa7, 0xba, 0xfb, 0xac,
		0x24, 0xb1, 0x82, 0x0c, 0xe1, 0x17, 0xb5, 0xda, 0x05, 0x4c, 0x90, 0x80, 0xd8, 0x82, 0x62, 0x2c,
		0x6d, 0xc8, 0x65, 0xac, 0xa1, 0xb6, 0x6f, 0x82, 0xbd, 0xfd, 0x5f, 0x06, 0x65, 0x7f, 0xda, 0x8b,
		0xee, 0xb8, 0x8a, 0x4e, 0x59, 0x8b, 0xb3, 0x5e, 0xfc, 0xf0, 0x6d, 0x2f, 0xbc, 0x31, 0x2b, 0xb6,
		0x97, 0x84, 0x88, 0x0e, 0x51, 0x9b, 0x03, 0x38, 0x56, 0x34, 0x8a, 0x80, 0x7f, 0x67, 0x85, 0x3f,
		0x70, 0xad, 0x99, 0x20, 0x5e, 0x2a, 0xf2, 0x97, 0x38
	};
	unsigned int const prv_bytes_len = 1193;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
	NSData * const publicKeyData = [NSData dataWithBytesNoCopy:(void *)pub_bytes length:pub_bytes_len freeWhenDone:NO];
	NSData * const privateKeyData = [NSData dataWithBytesNoCopy:(void *)prv_bytes length:prv_bytes_len freeWhenDone:NO];
#pragma clang diagnostic pop

	unsigned char const plaintext_bytes[] = {
		0x70, 0x6c, 0x61, 0x69, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x0a
	};
	unsigned int const plaintext_bytes_len = 10;

	unsigned char const ciphertext_bytes[] = {
		0x7e, 0x7f, 0x35, 0xf0, 0x10, 0x3b, 0xf5, 0x8b, 0x72, 0xb1, 0xad, 0xea, 0x4d, 0x50, 0xca, 0xfb,
		0xb9, 0xb8, 0x9c, 0x01, 0xe4, 0xbd, 0x63, 0x7a, 0xd5, 0x73, 0x80, 0x23, 0x9f, 0x9a, 0xf1, 0xff,
		0x63, 0xc4, 0x3a, 0xd6, 0xa3, 0xe4, 0xbb, 0x47, 0xd1, 0x64, 0x1e, 0x4f, 0xda, 0xf0, 0xe2, 0x1f,
		0x7e, 0x7e, 0x1e, 0x82, 0x25, 0xa5, 0xf9, 0x72, 0x17, 0x0c, 0x94, 0x27, 0xdb, 0x58, 0x94, 0x21,
		0xd0, 0x5c, 0xf4, 0x13, 0x41, 0xc4, 0x8c, 0x82, 0xcf, 0x41, 0xa4, 0xcf, 0x61, 0x9b, 0x14, 0x0e,
		0xd3, 0xbf, 0x7e, 0xcd, 0x2e, 0xbf, 0x76, 0x9b, 0x19, 0xc0, 0x56, 0x0a, 0x03, 0x58, 0x41, 0xb4,
		0x0f, 0xdf, 0xaf, 0x0b, 0x29, 0xe6, 0xe7, 0x89, 0x46, 0x6d, 0x35, 0x74, 0xd5, 0x16, 0x89, 0xe2,
		0xce, 0x6a, 0x8e, 0xc6, 0x14, 0x80, 0xfc, 0xf7, 0x22, 0x05, 0x43, 0x3d, 0x57, 0x97, 0x5f, 0x21,
		0xed, 0xbc, 0x32, 0x32, 0x16, 0x86, 0x7b, 0x8c, 0x89, 0xcd, 0xf9, 0x43, 0x47, 0x4a, 0x04, 0x7d,
		0x5d, 0xa1, 0x86, 0x0a, 0x72, 0x9f, 0x64, 0x4c, 0x23, 0xab, 0x5f, 0xe8, 0xac, 0x8a, 0x93, 0xf8,
		0x15, 0x22, 0x05, 0x82, 0xd0, 0x60, 0xb8, 0x8e, 0x88, 0x54, 0xa8, 0x1c, 0x99, 0xad, 0xc2, 0x62,
		0x86, 0x91, 0x8f, 0x2e, 0x66, 0x8d, 0x16, 0xb7, 0xe0, 0x3b, 0xe1, 0x8a, 0x2c, 0x6a, 0xa2, 0xe4,
		0x60, 0xf6, 0x05, 0x0c, 0x5b, 0x2c, 0xe2, 0x2b, 0xd4, 0xf8, 0x5d, 0xf6, 0x95, 0xcc, 0x5c, 0xb0,
		0x8f, 0xbf, 0x5d, 0xdb, 0xfa, 0x94, 0xf4, 0xff, 0x36, 0x65, 0x6b, 0x34, 0x75, 0x96, 0xaa, 0x59,
		0xf1, 0x81, 0x74, 0x71, 0x38, 0xeb, 0xe7, 0x9f, 0x50, 0xfb, 0x14, 0x24, 0xbe, 0x40, 0xc5, 0x9c,
		0xfd, 0x96, 0x9e, 0x66, 0x73, 0x3c, 0x20, 0xff, 0xa6, 0x64, 0xe4, 0x93, 0xe9, 0xa4, 0x44, 0x20
	};
	unsigned int const ciphertext_bytes_len = 256;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
	NSData * const plaintextDataExpected = [NSData dataWithBytesNoCopy:(void *)plaintext_bytes length:plaintext_bytes_len freeWhenDone:NO];
	NSData * const ciphertextData = [NSData dataWithBytesNoCopy:(void *)ciphertext_bytes length:ciphertext_bytes_len freeWhenDone:NO];
#pragma clang diagnostic pop

	[STSecurityKeychainAccess deleteRSAKeysForTag:keyTag error:NULL];

	{
		NSError *error = nil;
		BOOL status = [STSecurityKeychainAccess insertRSAKeypairWithPublicKeyData:publicKeyData privateKeyData:privateKeyData intoKeychainWithAccessibility:STSecurityKeychainItemAccessibleAlways tag:keyTag publicKey:&publicKey privateKey:&privateKey error:&error];
		XCTAssertTrue(status, @"Keychain could not insertion key pair");
		XCTAssertNil(error, @"Key insertion returned error: %@", error);
	}
	XCTAssertNotNil(publicKey, @"Key insertion resulted in no public key");
	XCTAssertNotNil(privateKey, @"Key insertion resulted in no private key");

	NSData *ciphertextDataDecrypted = nil;
	{
		NSError *error = nil;
		ciphertextDataDecrypted = [STSecurityRSAEncryption dataByDecryptingData:ciphertextData withPrivateKey:privateKey padding:STSecurityRSAPaddingPKCS1 error:&error];
		XCTAssertNotNil(ciphertextDataDecrypted);
		XCTAssertNil(error, @"error: %@", error);
	}
	XCTAssertEqualObjects(ciphertextDataDecrypted, plaintextDataExpected);

	{
		NSError *error = nil;
		BOOL status = [STSecurityKeychainAccess deleteRSAKeysForTag:keyTag error:&error];
		XCTAssertTrue(status, @"Keychain could not delete public key");
		XCTAssertNil(error, @"Public key deletion returned error: %@", error);
	}
}

@end
