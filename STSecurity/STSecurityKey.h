//
//  STSecurityKey.h
//  STSecurity
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface STSecurityPublicKey : NSObject
- (NSData *)keyData;
@end


@interface STSecurityPrivateKey : NSObject
@end
