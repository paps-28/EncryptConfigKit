import Foundation
import Security

public enum ECKeyManagerError: Error {
    case secureEnclaveUnavailable
    case accessControlCreationFailed
    case generationFailed
    case privateKeyNotFound
    case publicKeyNotFound
    case publicKeyExportFailed
    case loadFailed(OSStatus)
    case deleteFailed(OSStatus)
    case algorithmNotSupported
    case decryptionFailed
}
