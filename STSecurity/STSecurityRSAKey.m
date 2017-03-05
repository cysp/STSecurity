//
//  STSecurityRSAKey.m
//  STSecurity
//
//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
//  Copyright (c) 2012 Scott Talbot. All rights reserved.
//

#if ! (defined(__has_feature) && __has_feature(objc_arc))
# error "STSecurity must be compiled with ARC enabled"
#endif

@import Security;

#import <STSecurity/STSecurity.h>


@implementation STSecurityRSAPublicKey {
	SecKeyRef _keyRef;
	NSData *_keyData;
}

#pragma mark - Init/Dealloc

- (id)initWithKeyRef:(SecKeyRef)keyRef {
	return [self initWithKeyRef:keyRef keyData:nil];
}

- (id)initWithKeyRef:(SecKeyRef)keyRef keyData:(NSData *)keyData {
	NSParameterAssert(keyRef);
	NSParameterAssert([keyData length]);
	if (!keyRef || ![keyData length]) {
		return nil;
	}
	if ((self = [super init])) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
		_keyRef = (SecKeyRef)CFRetain(keyRef);
#pragma clang diagnostic pop
		_keyData = [keyData copy];
	}
	return self;
}

- (void)dealloc {
	if (_keyRef) {
		CFRelease(_keyRef);
		_keyRef = nil;
	}
}


#pragma mark - Information

- (SecKeyRef)keyRef {
	return _keyRef;
}

- (NSUInteger)blockSize {
	return SecKeyGetBlockSize(_keyRef);
}

- (NSData *)keyData {
	return _keyData;
}

@end


@implementation STSecurityRSAPrivateKey {
	SecKeyRef _keyRef;
}

#pragma mark - Init/Dealloc

- (id)initWithKeyRef:(SecKeyRef)keyRef {
	NSParameterAssert(keyRef);
	if (!keyRef) {
		return nil;
	}
	if ((self = [super init])) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
		_keyRef = (SecKeyRef)CFRetain(keyRef);
#pragma clang diagnostic pop
	}
	return self;
}

- (void)dealloc {
	if (_keyRef) {
		CFRelease(_keyRef);
		_keyRef = nil;
	}
}


#pragma mark - Information

- (SecKeyRef)keyRef {
	return _keyRef;
}

- (NSUInteger)blockSize {
	return SecKeyGetBlockSize(_keyRef);
}

@end
