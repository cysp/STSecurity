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

@import Foundation;

NS_ASSUME_NONNULL_BEGIN


extern NSString * const STSecurityRandomizationErrorDomain;


@interface STSecurityRandomization : NSObject

+ (NSData * __nullable)dataWithRandomBytesOfLength:(NSUInteger)count NS_SWIFT_UNAVAILABLE("");
+ (NSData * __nullable)dataWithRandomBytesOfLength:(NSUInteger)count error:(NSError * __autoreleasing __nullable * __nullable)error NS_SWIFT_NAME(dataWithRandomBytesOfLength(_:));

@end

NS_ASSUME_NONNULL_END
