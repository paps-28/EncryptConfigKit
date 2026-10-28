import Foundation
import Security
import Testing
@testable import EncryptConfigCore

struct RSAKeyPersistenceTests {
    @Test func loadFailureDoesNotReplaceKey() {
        let store = FailingRSAStore()
        let manager = RSAKeyManager(generator: DefaultRSAKeyPairGenerator(), store: store)
        #expect(throws: (any Error).self) { try manager.generateKeyPairIfNeeded() }
        #expect(!store.saved)
    }


}

private final class FailingRSAStore: PrivateKeyStoring {
    var saved = false
    func save(_ key: SecKey, tag: Data) throws { saved = true }
    func load(tag: Data) throws -> SecKey? {
        throw RSAKeyManagerError.loadFailed(errSecInteractionNotAllowed)
    }
    func delete(tag: Data) throws {}
}
