//  Copyright (c) 2014 Scott Talbot. All rights reserved.

import XCTest


class STSecurityRandomizationSwiftTests: XCTestCase {

	func testRandom0() {
		let count = 0
		let randomData: Data;
		do {
			try randomData = STSecurityRandomization.dataWithRandomBytesOfLength(UInt(count))
		} catch (let error) {
			XCTAssertNil(error)
			return;
		}

		XCTAssertNotNil(randomData, "STSecurityRandomization returned nil")
		XCTAssertEqual(randomData.count, count, "STSecurityRandomization returned incorrect length of random data")
	}

	func testRandom1() {
		let count = 1
		let randomData: Data;
		do {
			try randomData = STSecurityRandomization.dataWithRandomBytesOfLength(UInt(count))
		} catch (let error) {
			XCTAssertNil(error)
			return;
		}

		XCTAssertNotNil(randomData, "STSecurityRandomization returned nil")
		XCTAssertEqual(randomData.count, count, "STSecurityRandomization returned incorrect length of random data")
	}

	func testRandom16() {
		let count = 16
		let randomData: Data;
		do {
			try randomData = STSecurityRandomization.dataWithRandomBytesOfLength(UInt(count))
		} catch (let error) {
			XCTAssertNil(error)
			return;
		}

		XCTAssertNotNil(randomData, "STSecurityRandomization returned nil")
		XCTAssertEqual(randomData.count, count, "STSecurityRandomization returned incorrect length of random data")
	}

}
