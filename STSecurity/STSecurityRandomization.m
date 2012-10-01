//
//  STSecurity.m
//  STSecurity
//
//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#if ! (defined(__has_feature) && __has_feature(objc_arc))
# error "STReachability must be compiled with ARC enabled"
#endif

#import "STSecurityRandomization.h"

#import <Security/Security.h>


NSString * const STSecurityRandomizationErrorDomain = @"STSecurityRandomizationError";


@implementation STSecurityRandomization

+ (NSData *)dataWithRandomBytesOfLength:(NSUInteger)count {
	return [self dataWithRandomBytesOfLength:count error:NULL];
}

+ (NSData *)dataWithRandomBytesOfLength:(NSUInteger)count error:(NSError * __autoreleasing *)error {
	if (count == 0) {
		return [NSData data];
	}
	
	uint8_t *bytes = malloc(count);

	OSStatus err = SecRandomCopyBytes(NULL, count, bytes);
	if (err != noErr) {
		free(bytes), bytes = NULL;
		if (error) {
			*error = [NSError errorWithDomain:STSecurityRandomizationErrorDomain code:errno userInfo:nil];
		}
		return nil;
	}

	return [[NSData alloc] initWithBytesNoCopy:bytes length:count freeWhenDone:YES];
}

@end
