//
//  STSecurityRSAKey.h
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


@interface STSecurityRSAPublicKey : NSObject
@property (nonatomic,copy,nullable,readonly) NSData *keyData;
@end


@interface STSecurityRSAPrivateKey : NSObject
@end

NS_ASSUME_NONNULL_END
