//  Copyright (c) 2014 Scott Talbot. All rights reserved.

import XCTest


let service = "STSecurityTest"


class STSecurityKeychainAccessPasswordTests: XCTestCase {

	override func setUp() {
		STSecurityKeychainAccess.deletePasswordsForService(service)
	}

	func testFetchNonexistent() {
		let username = "username"

		var error: NSError?
		let password: String? = STSecurityKeychainAccess.passwordForUsername(username, service: service, error: &error)
		XCTAssertNil(password)
		XCTAssertNotNil(error)
	}

	func testRoundtrip() {
		let username = "username"
		let password = "password"

		let status = STSecurityKeychainAccess.setPassword(password, forUsername: username, service: service)
		XCTAssertTrue(status)

		var error: NSError?
		let fetchedPassword: String? = STSecurityKeychainAccess.passwordForUsername(username, service: service, error: &error)
		XCTAssertNotNil(fetchedPassword)
		XCTAssertNil(error)
		XCTAssertEqual(password, fetchedPassword!)
	}

	func testMultipleInsertion() {
		let username = "username"
		let password = "password";

		var error: NSError?

		let status1 = STSecurityKeychainAccess.setPassword(password, forUsername: username, service: service, error: &error)
		XCTAssertTrue(status1)
		XCTAssertNil(error)

		let status2 = STSecurityKeychainAccess.setPassword(password, forUsername: username, service: service, error: &error)
		XCTAssertFalse(status2)
		XCTAssertNotNil(error)

		let status3 = STSecurityKeychainAccess.setPassword(password, forUsername: username, service: service, withAccessibility: .AccessibleAlways, overwriteExisting: true, error: &error)
		XCTAssertTrue(status3)
		XCTAssertNil(error)

		let status4 = STSecurityKeychainAccess.setPassword(password, forUsername: username, service: service, error: &error)
		XCTAssertFalse(status4)
		XCTAssertNotNil(error)

		let status5 = STSecurityKeychainAccess.setPassword(password, forUsername: username, service: service, withAccessibility: .AccessibleAlwaysThisDeviceOnly, overwriteExisting: true, error: &error)
		XCTAssertTrue(status5)
		XCTAssertNil(error)

		let fetchedPassword: String? = STSecurityKeychainAccess.passwordForUsername(username, service: service, error: &error)
		XCTAssertNotNil(fetchedPassword);
		XCTAssertEqual(password, fetchedPassword!);
		XCTAssertNil(error)

		let status6 = STSecurityKeychainAccess.deletePasswordForUsername(username, service: service, error: &error)
		XCTAssertTrue(status6)
		XCTAssertNil(error)
	}

}
