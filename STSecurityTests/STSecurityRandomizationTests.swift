//  Copyright (c) 2014 Scott Talbot. All rights reserved.

import XCTest


class STSecurityTests: XCTestCase {

	func testRandom0() {
		let count: UInt = 0
		var error: NSError?
		let randomData = STSecurityRandomization.dataWithRandomBytesOfLength(count, error: &error)

		XCTAssertNotNil(randomData, "STSecurityRandomization returned nil, error: \(error)")
		XCTAssertEqual(UInt(randomData.length), count, "STSecurityRandomization returned incorrect length of random data")
	}

	func testRandom1() {
		let count: UInt = 0
		var error: NSError?
		let randomData = STSecurityRandomization.dataWithRandomBytesOfLength(count, error: &error)
		XCTAssertNotNil(randomData, "STSecurityRandomization returned nil, error: \(error)")
		XCTAssertEqual(UInt(randomData.length), count, "STSecurityRandomization returned incorrect length of random data")
	}

	func testRandom16() {
		let count: UInt = 16
		var error: NSError?
		let randomData = STSecurityRandomization.dataWithRandomBytesOfLength(count, error: &error)
		XCTAssertNotNil(randomData, "STSecurityRandomization returned nil, error: \(error)")
		XCTAssertEqual(UInt(randomData.length), count, "STSecurityRandomization returned incorrect length of random data")
	}

}
