//
//  STSecurityRandomizationTests.m
//  STSecurityRandomizationTests
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

@import XCTest;

#import "STSecurityRandomization.h"


@interface STSecurityRandomizationTests : XCTestCase
@end

@implementation STSecurityRandomizationTests

- (void)testRandom0 {
	NSUInteger const count = 0;
	NSError *error = nil;
	NSData * const randomData = [STSecurityRandomization dataWithRandomBytesOfLength:count error:&error];
	XCTAssertNotNil(randomData, @"STSecurityRandomization returned nil, error: %@", error);
	XCTAssertEqual([randomData length], count, @"STSecurityRandomization returned incorrect length of random data");
}

- (void)testRandom1 {
	NSUInteger const count = 1;
	NSError *error = nil;
	NSData * const randomData = [STSecurityRandomization dataWithRandomBytesOfLength:count error:&error];
	XCTAssertNotNil(randomData, @"STSecurityRandomization returned nil, error: %@", error);
	XCTAssertEqual([randomData length], count, @"STSecurityRandomization returned incorrect length of random data");
}

- (void)testRandom16 {
	NSUInteger const count = 16;
	NSError *error = nil;
	NSData * const randomData = [STSecurityRandomization dataWithRandomBytesOfLength:count error:&error];
	XCTAssertNotNil(randomData, @"STSecurityRandomization returned nil, error: %@", error);
	XCTAssertEqual([randomData length], count, @"STSecurityRandomization returned incorrect length of random data");
}

@end
