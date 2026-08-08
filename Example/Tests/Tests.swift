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

    func testBIP32KeystoreDecryptsWhatItEncrypted() throws {
        let password = "password"
        let mnemonics = try Mnemonics(entropy: Data(repeating: 0, count: 16))
        let keystore = try BIP32Keystore(mnemonics: mnemonics, password: password)
        let account = try XCTUnwrap(keystore.addresses.first)

        let privateKey = try keystore.UNSAFE_getPrivateKeyData(password: password, account: account)

        XCTAssertEqual(privateKey.count, 32)
    }
}
