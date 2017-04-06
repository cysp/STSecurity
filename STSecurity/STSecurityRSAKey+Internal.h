//
//  STSecurityRSAKey+Internal.h
//  STSecurity
//
//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import <STSecurity/STSecurityRSAKey.h>

NS_ASSUME_NONNULL_BEGIN


@interface STSecurityRSAPublicKey (Internal)
- (id)initWithKeyRef:(SecKeyRef)keyRef keyData:(NSData * __nullable)keyData;
- (SecKeyRef)keyRef NS_RETURNS_INNER_POINTER;
- (NSUInteger)blockSize;
@end


@interface STSecurityRSAPrivateKey (Internal)
- (id)initWithKeyRef:(SecKeyRef)keyRef;
- (SecKeyRef)keyRef NS_RETURNS_INNER_POINTER;
- (NSUInteger)blockSize;
@end

NS_ASSUME_NONNULL_END
