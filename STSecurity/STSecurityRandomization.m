//
//  STSecurity.m
//  STSecurity
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

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
