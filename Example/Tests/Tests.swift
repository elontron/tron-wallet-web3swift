import XCTest
@testable import web3swift

class Tests: XCTestCase {

    /// BIP32Keystore encrypts 82 bytes, which is not a multiple of the AES block size,
    /// so PKCS7 makes CCCryptorFinal emit a block of its own. Writing that block at the
    /// wrong offset corrupts the ciphertext without any call reporting an error.
    func testAESRoundTripWithFinalBlock() throws {
        let key = Data.random(length: 16)
        let iv = Data.random(length: 16)
        let plaintext = Data.random(length: 82)

        let combinations: [(AesMode, AESPadding)] = [(.cbc, .pkcs7), (.ctr, .noPadding)]
        for (mode, padding) in combinations {
            let cipher = AES(key: key.bytes, blockMode: mode.blockMode(iv), padding: padding)
            let encrypted = try cipher.encrypt(plaintext)
            XCTAssertNotEqual(encrypted.prefix(plaintext.count), plaintext)
            XCTAssertEqual(try cipher.decrypt(encrypted), plaintext, "\(mode) round trip")
        }
    }

    /// `bytesFromBase58` sized its buffer as `length - leadingOnes`, which goes negative
    /// once a string is mostly '1's and traps in `Array(repeating:count:)` before a single
    /// character is decoded. Address fields feed untrusted strings straight into this.
    func testBase58DecodesLeadingZeroRuns() {
        for count in 1 ... 8 {
            XCTAssertEqual(Base58.bytesFromBase58(String(repeating: "1", count: count)),
                           [UInt8](repeating: 0, count: count),
                           "\(count) leading zero bytes")
        }
    }

    func testBase58RoundTripsAndRejectsGarbage() {
        // 0x00 is the zero digit, 0x3a is 58 == 1*58 + 0: the first two-digit value.
        XCTAssertEqual(Base58.base58FromBytes([0x00]), "1")
        XCTAssertEqual(Base58.base58FromBytes([0x3a]), "21")
        XCTAssertEqual(Base58.bytesFromBase58("21"), [0x3a])

        let address: [UInt8] = [0x41] + (0 ..< 20).map { UInt8($0) }
        let encoded = address.base58CheckEncodedString
        XCTAssertEqual(encoded.count, 34)
        XCTAssertEqual(encoded.first, "T")
        XCTAssertEqual(encoded.base58CheckDecodedBytes, address)

        XCTAssertEqual(Base58.bytesFromBase58("0OIl"), [])
        XCTAssertNil(String(encoded.dropLast()).base58CheckDecodedBytes)
    }

    func testBIP32KeystoreDecryptsWhatItEncrypted() throws {
        let password = "password"
        let mnemonics = try Mnemonics(entropy: Data(repeating: 0, count: 16))
        let keystore = try BIP32Keystore(mnemonics: mnemonics, password: password)
        let account = try XCTUnwrap(keystore.addresses.first)

        let privateKey = try keystore.UNSAFE_getPrivateKeyData(password: password, account: account)

        XCTAssertEqual(privateKey.count, 32)
    }
}
