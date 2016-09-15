//
//  STSecurityKeychainAccess.h
//  STSecurity
//
//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
//  Copyright © 2012-2016 Scott Talbot. All rights reserved.
//


static inline CFTypeRef STSecurityKeychainItemAccessibilityToCFType(enum STSecurityKeychainItemAccessibility accessibility) {
	switch (accessibility) {
		case STSecurityKeychainItemAccessibleWhenUnlocked:
			return kSecAttrAccessibleWhenUnlocked;
		case STSecurityKeychainItemAccessibleWhenUnlockedThisDeviceOnly:
			return kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
		case STSecurityKeychainItemAccessibleAfterFirstUnlock:
			return kSecAttrAccessibleAfterFirstUnlock;
		case STSecurityKeychainItemAccessibleAfterFirstUnlockThisDeviceOnly:
			return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
		case STSecurityKeychainItemAccessibleAlways:
			return kSecAttrAccessibleAlways;
		case STSecurityKeychainItemAccessibleAlwaysThisDeviceOnly:
			return kSecAttrAccessibleAlwaysThisDeviceOnly;
		case STSecurityKeychainItemAccessibleWhenPasscodeSetThisDeviceOnly:
			return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly;
	}
	NSCAssert(0, @"unreachable", nil);
	return kSecAttrAccessibleWhenUnlocked;
}
