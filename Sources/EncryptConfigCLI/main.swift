//
//  main.swift
//  EncryptConfigKit
//
//  Created by Pedro Alberto Parra on 30/06/26.
//

import Foundation

do {
    let arguments = try Arguments()
    try EncryptConfigCommand().run(arguments: arguments)
} catch {
    fputs("encrypt-config error: \(error)\n", stderr)
    exit(1)
}
