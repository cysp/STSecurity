//
//  STSecurityKeychainAccessPasswordTests.m
//  STSecurity
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import "STSecurityKeychainAccessPasswordTests.h"

#import "STSecurityKeychainAccess.h"


static NSString * const service = @"STSecurityTest";


@implementation STSecurityKeychainAccessPasswordTests

- (void)setUp {
	[STSecurityKeychainAccess deletePasswordsForService:service];
}

- (void)testFetchNonexistent {
	NSString * const username = @"username";

	{
		NSError *error = nil;
		NSString * const password = [STSecurityKeychainAccess passwordForUsername:username service:service error:&error];
		STAssertNil(password, nil);
		STAssertNotNil(error, nil);
	}
}

- (void)testRoundtrip {
	NSString * const username = @"username";
	NSString * const password = @"password";

	{
		NSError *error = nil;
		BOOL const status = [STSecurityKeychainAccess setPassword:password forUsername:username service:service error:&error];
		STAssertTrue(status, nil);
		STAssertNil(error, nil);
	}

	{
		NSError *error = nil;
		NSString * const fetchedPassword = [STSecurityKeychainAccess passwordForUsername:username service:service error:&error];
		STAssertNotNil(fetchedPassword, nil);
		STAssertNil(error, @"error: %@", error);
		STAssertEqualObjects(password, fetchedPassword, nil);
	}
}

- (void)testMultipleInsertion {
	NSString * const username = @"username";
	NSString * const password = @"password";

	{
		NSError *error = nil;
		BOOL const status = [STSecurityKeychainAccess setPassword:password forUsername:username service:service error:&error];
		STAssertTrue(status, nil);
		STAssertNil(error, nil);
	}

	{
		NSError *error = nil;
		BOOL const status = [STSecurityKeychainAccess setPassword:password forUsername:username service:service error:&error];
		STAssertFalse(status, nil);
		STAssertNotNil(error, @"error: %@", error);
	}

	{
		NSError *error = nil;
		BOOL const status = [STSecurityKeychainAccess setPassword:password forUsername:username service:service withAccessibility:STSecurityKeychainItemAccessibleAlways overwriteExisting:YES error:&error];
		STAssertTrue(status, nil);
		STAssertNil(error, @"error: %@", error);
	}

	{
		NSError *error = nil;
		BOOL const status = [STSecurityKeychainAccess setPassword:password forUsername:username service:service error:&error];
		STAssertFalse(status, nil);
		STAssertNotNil(error, @"error: %@", error);
	}

	{
		NSError *error = nil;
		BOOL const status = [STSecurityKeychainAccess setPassword:password forUsername:username service:service withAccessibility:STSecurityKeychainItemAccessibleAlwaysThisDeviceOnly overwriteExisting:YES error:&error];
		STAssertTrue(status, nil);
		STAssertNil(error, @"error: %@", error);
	}

	{
		NSError *error = nil;
		NSString * const fetchedPassword = [STSecurityKeychainAccess passwordForUsername:username service:service error:&error];
		STAssertNotNil(fetchedPassword, nil);
		STAssertNil(error, @"error: %@", error);
		STAssertEqualObjects(password, fetchedPassword, nil);
	}

	{
		NSError *error = nil;
		BOOL const status = [STSecurityKeychainAccess deletePasswordForUsername:username service:service error:&error];
		STAssertTrue(status, nil);
		STAssertNil(error, @"error: %@", error);
	}
}

@end
