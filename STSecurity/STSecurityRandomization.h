//
//  STSecurity.h
//  STSecurity
//
//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import <Foundation/Foundation.h>


extern NSString * const STSecurityRandomizationErrorDomain;


@interface STSecurityRandomization : NSObject

+ (NSData *)dataWithRandomBytesOfLength:(NSUInteger)count;
+ (NSData *)dataWithRandomBytesOfLength:(NSUInteger)count error:(NSError * __autoreleasing *)error;

@end