//
//  STSecurityKey+Internal.h
//  STSecurity
//
//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import "STSecurityKey.h"


@interface STSecurityPublicKey (Internal)
- (id)initWithKeyRef:(SecKeyRef)keyRef keyData:(NSData *)keyData;
- (SecKeyRef)keyRef NS_RETURNS_INNER_POINTER;
- (NSUInteger)blockSize;
@end


@interface STSecurityPrivateKey (Internal)
- (id)initWithKeyRef:(SecKeyRef)keyRef;
- (SecKeyRef)keyRef NS_RETURNS_INNER_POINTER;
- (NSUInteger)blockSize;
@end
