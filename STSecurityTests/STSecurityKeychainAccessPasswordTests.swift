//  Copyright (c) 2014 Scott Talbot. All rights reserved.

import XCTest


let service = "STSecurityTest"


class STSecurityKeychainAccessPasswordSwiftTests: XCTestCase {

	override func setUp() {
		do {
			try STSecurityKeychainAccess.deletePasswords(service: service)
		} catch {}
	}

	func testFetchNonexistent() {
		let username = "username"

		var password: String?
		do {
			password = try STSecurityKeychainAccess.password(service: service, username: username)
			XCTAssertTrue(false)
		} catch (let error) {
			XCTAssertNotNil(error)
		}
		XCTAssertNil(password)
	}

	func testRoundtrip() {
		let username = "username"
		let password = "password"

		do {
			try STSecurityKeychainAccess.setPassword(service: service, username: username, password: password)
		} catch (let error) {
			XCTAssertNil(error)
		}

		var fetchedPassword: String?
		do {
			fetchedPassword = try STSecurityKeychainAccess.password(service: service, username: username)
		} catch (let error) {
			XCTAssertTrue(false)
			XCTAssertNotNil(error)
		}
		XCTAssertNotNil(fetchedPassword)
		XCTAssertEqual(password, fetchedPassword)
	}

	func testMultipleInsertion() {
		let username = "username"
		let password = "password";

		do {
			try STSecurityKeychainAccess.setPassword(service: service, username: username, password: password)
		} catch (let error) {
			XCTAssertTrue(false)
			XCTAssertNotNil(error)
		}

		do {
			try STSecurityKeychainAccess.setPassword(service: service, username: username, password: password)
			XCTAssertTrue(false)
		} catch (let error) {
			XCTAssertNotNil(error)
		}

		do {
			try STSecurityKeychainAccess.setPassword(service: service, username: username, password: password, options: STSecurityKeychainWritingOptions(overwriteExisting: true,accessibility: .accessibleAlways))
		} catch (let error) {
			XCTAssertTrue(false)
			XCTAssertNotNil(error)
		}

		do {
			try STSecurityKeychainAccess.setPassword(service: service, username: username, password: password)
			XCTAssertTrue(false)
		} catch (let error) {
			XCTAssertNotNil(error)
		}

		do {
			try STSecurityKeychainAccess.setPassword(service: service, username: username, password: password, options: STSecurityKeychainWritingOptions(overwriteExisting: true, accessibility: .accessibleAlwaysThisDeviceOnly))
		} catch (let error) {
			XCTAssertTrue(false)
			XCTAssertNotNil(error)
		}

		var fetchedPassword: String?
		do {
			fetchedPassword = try STSecurityKeychainAccess.password(service: service, username: username)
		} catch (let error) {
			XCTAssertTrue(false)
			XCTAssertNotNil(error)
		}
		XCTAssertNotNil(fetchedPassword);
		XCTAssertEqual(password, fetchedPassword);

		do {
			try STSecurityKeychainAccess.deletePassword(service: service, username: username)
		} catch (let error) {
			XCTAssertTrue(false)
			XCTAssertNotNil(error)
		}
	}

}
