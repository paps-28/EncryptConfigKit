//
//  RSAPublicKeyX509Exporter.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 28/07/26.
//


import Foundation

struct RSAPublicKeyX509Exporter {

    func wrapPKCS1InX509(_ pkcs1Data: Data) -> Data {
        /*
         AlgorithmIdentifier:

         SEQUENCE {
             OBJECT IDENTIFIER rsaEncryption
             NULL
         }

         OID: 1.2.840.113549.1.1.1
         */
        let rsaAlgorithmIdentifier = Data([
            0x30, 0x0D,
            0x06, 0x09,
            0x2A, 0x86, 0x48, 0x86,
            0xF7, 0x0D, 0x01, 0x01, 0x01,
            0x05, 0x00
        ])

        /*
         SubjectPublicKey es un BIT STRING.

         El primer byte 0x00 indica que no hay bits sin utilizar
         al final del BIT STRING.
         */
        var bitStringContent = Data([0x00])
        bitStringContent.append(pkcs1Data)

        let bitString = encodeDER(
            tag: 0x03,
            value: bitStringContent
        )

        var subjectPublicKeyInfo = Data()
        subjectPublicKeyInfo.append(rsaAlgorithmIdentifier)
        subjectPublicKeyInfo.append(bitString)

        return encodeDER(
            tag: 0x30,
            value: subjectPublicKeyInfo
        )
    }

    private func encodeDER(
        tag: UInt8,
        value: Data
    ) -> Data {
        var result = Data([tag])
        result.append(encodeDERLength(value.count))
        result.append(value)
        return result
    }

    private func encodeDERLength(_ length: Int) -> Data {
        guard length >= 128 else {
            return Data([UInt8(length)])
        }

        var remaining = length
        var bytes: [UInt8] = []

        while remaining > 0 {
            bytes.insert(
                UInt8(remaining & 0xFF),
                at: 0
            )

            remaining >>= 8
        }

        return Data([
            0x80 | UInt8(bytes.count)
        ] + bytes)
    }
}