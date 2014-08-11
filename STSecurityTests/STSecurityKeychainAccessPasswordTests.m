//
//  STSecurityKeychainAccessPasswordTests.m
//  STSecurity
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

@import XCTest;

#import "STSecurityKeychainAccess.h"


static NSString * const service = @"STSecurityTest";


@interface STSecurityKeychainAccessPasswordTests : XCTestCase
@end

@implementation STSecurityKeychainAccessPasswordTests

- (void)setUp {
	[STSecurityKeychainAccess deletePasswordsForService:service];
}

- (void)testFetchNonexistent {
	NSString * const username = @"username";

	{
		NSError *error = nil;
		NSString * const password = [STSecurityKeychainAccess passwordForUsername:username service:service error:&error];
		XCTAssertNil(password);
		XCTAssertNotNil(error);
	}
}

- (void)testRoundtrip {
	NSString * const username = @"username";
	NSString * const password = @"password";

	{
		NSError *error = nil;
		BOOL const status = [STSecurityKeychainAccess setPassword:password forUsername:username service:service error:&error];
		XCTAssertTrue(status);
		XCTAssertNil(error);
	}

	{
		NSError *error = nil;
		NSString * const fetchedPassword = [STSecurityKeychainAccess passwordForUsername:username service:service error:&error];
		XCTAssertNotNil(fetchedPassword);
		XCTAssertNil(error, @"error: %@", error);
		XCTAssertEqualObjects(password, fetchedPassword);
	}
}

- (void)testMultipleInsertion {
	NSString * const username = @"username";
	NSString * const password = @"password";

	{
		NSError *error = nil;
		BOOL const status = [STSecurityKeychainAccess setPassword:password forUsername:username service:service error:&error];
		XCTAssertTrue(status);
		XCTAssertNil(error);
	}

	{
		NSError *error = nil;
		BOOL const status = [STSecurityKeychainAccess setPassword:password forUsername:username service:service error:&error];
		XCTAssertFalse(status);
		XCTAssertNotNil(error, @"error: %@", error);
	}

	{
		STSecurityKeychainWritingOptions * const options = [[STSecurityKeychainWritingOptions alloc] init];
		options.accessibility = STSecurityKeychainItemAccessibleAlways;
		options.overwriteExisting = YES;

		NSError *error = nil;
		BOOL const status = [STSecurityKeychainAccess setPassword:password forUsername:username service:service withOptions:options error:&error];
		XCTAssertTrue(status);
		XCTAssertNil(error, @"error: %@", error);
	}

	{
		NSError *error = nil;
		BOOL const status = [STSecurityKeychainAccess setPassword:password forUsername:username service:service error:&error];
		XCTAssertFalse(status);
		XCTAssertNotNil(error, @"error: %@", error);
	}

	{
		STSecurityKeychainWritingOptions * const options = [[STSecurityKeychainWritingOptions alloc] init];
		options.accessibility = STSecurityKeychainItemAccessibleAlwaysThisDeviceOnly;
		options.overwriteExisting = YES;

		NSError *error = nil;
		BOOL const status = [STSecurityKeychainAccess setPassword:password forUsername:username service:service withOptions:options error:&error];
		XCTAssertTrue(status);
		XCTAssertNil(error, @"error: %@", error);
	}

	{
		NSError *error = nil;
		NSString * const fetchedPassword = [STSecurityKeychainAccess passwordForUsername:username service:service error:&error];
		XCTAssertNotNil(fetchedPassword);
		XCTAssertNil(error, @"error: %@", error);
		XCTAssertEqualObjects(password, fetchedPassword);
	}

	{
		NSError *error = nil;
		BOOL const status = [STSecurityKeychainAccess deletePasswordForUsername:username service:service error:&error];
		XCTAssertTrue(status);
		XCTAssertNil(error, @"error: %@", error);
	}
}

@end
