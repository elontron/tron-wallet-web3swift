
import Foundation
import scrypt

public func scrypt(password: String, salt: Data, length: Int, N: Int, R: Int, P: Int) -> Data? {
    let passwordData = password.data
    var derivedKey = Data(count: length)
    let derivedKeyCount = derivedKey.count
    let passCount = passwordData.count
    let saltCount = salt.count
    let status = derivedKey.withUnsafeMutableBytes { (outPtr: UnsafeMutablePointer<UInt8>) -> Int32 in
        passwordData.withUnsafeBytes { (passPtr: UnsafePointer<UInt8>) -> Int32 in
            salt.withUnsafeBytes { (saltPtr: UnsafePointer<UInt8>) -> Int32 in
                crypto_scrypt(passPtr, passCount, saltPtr, saltCount, UInt64(N), UInt32(R), UInt32(P), outPtr, derivedKeyCount)
            }
        }
    }
    guard status == 0 else { return nil }
    return derivedKey
}
