//
//  STSecurity.h
//  STSecurity
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import <Foundation/Foundation.h>


extern NSString * const STSecurityRandomizationErrorDomain;


@interface STSecurityRandomization : NSObject

+ (NSData *)dataWithRandomBytesOfLength:(NSUInteger)count;
+ (NSData *)dataWithRandomBytesOfLength:(NSUInteger)count error:(NSError * __autoreleasing *)error;

@end
