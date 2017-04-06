//
//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
//  Copyright © 2016 Scott Talbot. All rights reserved.


extension STSecurityKeychainReadingOptions {
	convenience init(prompt: String? = nil) {
		self.init()
		self.prompt = prompt
	}
}

extension STSecurityKeychainWritingOptions {
	convenience init(overwriteExisting: Bool? = nil, accessibility: STSecurityKeychainItemAccessibility = .accessibleWhenUnlocked, accessControl: STSecurityKeychainItemAccessControl = [], prompt: String? = nil) {
		self.init()
		if let b = overwriteExisting {
			self.overwriteExisting = b
		}
		self.accessibility = accessibility
		self.accessControl = accessControl
		self.prompt = prompt
	}
}

extension STSecurityKeychainAccess {

	class func containsPassword(service: String, username: String) throws -> Bool {
		var error: NSError? = nil
		let status = STSecurityKeychainAccess.__containsPassword(forUsername: username, service: service, error: &error)
		if !status {
			if let e = error {
				throw e
			}
			throw NSError(domain: STSecurityKeychainAccessErrorDomain, code: 0, userInfo: nil)
		}
		return status
	}

	class func password(service: String, username: String, options: STSecurityKeychainReadingOptions? = nil) throws -> String {
		do {
			return try STSecurityKeychainAccess.__password(forUsername: username, service: service, with: options)
		} catch (let error) {
			throw error
		}
	}

	class func setPassword(service: String, username: String, password: String, options: STSecurityKeychainWritingOptions? = nil) throws {
		do {
			return try STSecurityKeychainAccess.__setPassword(password, forUsername: username, service: service, with: options)
		} catch (let error) {
			throw error
		}
	}

	class func deletePassword(service: String, username: String, options: STSecurityKeychainWritingOptions? = nil) throws {
		do {
			return try STSecurityKeychainAccess.__deletePassword(forUsername: username, service: service, with: options)
		} catch (let error) {
			throw error
		}
	}

	class func deletePasswords(service: String, options: STSecurityKeychainWritingOptions? = nil) throws {
		do {
			return try STSecurityKeychainAccess.__deletePasswords(forService: service, with: options)
		} catch (let error) {
			throw error
		}
	}

}
