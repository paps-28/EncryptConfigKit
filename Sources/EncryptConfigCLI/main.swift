//
//  main.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 30/06/26.
//

import EncryptConfigCore
import Foundation

let environment = ProcessInfo.processInfo.environment

guard
    let inputPath = environment["INPUT_FILE"],
    let outputPath = environment["OUTPUT_FILE"],
    let password = environment["CONFIG_KEY"]
else {
    fatalError("Missing INPUT_FILE, OUTPUT_FILE or CONFIG_KEY")
}

let inputURL = URL(fileURLWithPath: inputPath)
let outputURL = URL(fileURLWithPath: outputPath)

let inputData = try Data(contentsOf: inputURL)

let encrypted = try EncryptionService().encrypt(
    data: inputData,
    password: password
)

let encoder = JSONEncoder()
encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

let outputData = try encoder.encode(encrypted)

try FileManager.default.createDirectory(
    at: outputURL.deletingLastPathComponent(),
    withIntermediateDirectories: true
)

try outputData.write(to: outputURL)

print("Encrypted config generated at: \(outputPath)")
