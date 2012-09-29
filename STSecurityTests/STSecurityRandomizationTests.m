//
//  STSecurityRandomizationTests.m
//  STSecurityRandomizationTests
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import "STSecurityRandomizationTests.h"

#import "STSecurityRandomization.h"


@implementation STSecurityRandomizationTests

- (void)testRandom0 {
	NSUInteger const count = 0;
	NSError *error = nil;
	NSData * const randomData = [STSecurityRandomization dataWithRandomBytesOfLength:count error:&error];
	STAssertNotNil(randomData, @"STSecurityRandomization returned nil, error: %@", error);
	STAssertEquals([randomData length], count, @"STSecurityRandomization returned incorrect length of random data");
}

- (void)testRandom1 {
	NSUInteger const count = 1;
	NSError *error = nil;
	NSData * const randomData = [STSecurityRandomization dataWithRandomBytesOfLength:count error:&error];
	STAssertNotNil(randomData, @"STSecurityRandomization returned nil, error: %@", error);
	STAssertEquals([randomData length], count, @"STSecurityRandomization returned incorrect length of random data");
}

- (void)testRandom16 {
	NSUInteger const count = 16;
	NSError *error = nil;
	NSData * const randomData = [STSecurityRandomization dataWithRandomBytesOfLength:count error:&error];
	STAssertNotNil(randomData, @"STSecurityRandomization returned nil, error: %@", error);
	STAssertEquals([randomData length], count, @"STSecurityRandomization returned incorrect length of random data");
}

@end
