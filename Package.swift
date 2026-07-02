// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "EncryptConfigKit",
    platforms: [
        .iOS(.v15),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "EncryptConfigCore",
            targets: ["EncryptConfigCore"]
        ),
        .library(
            name: "EncryptConfigRuntime",
            targets: ["EncryptConfigRuntime"]
        ),
        .executable(
            name: "encrypt-config",
            targets: ["EncryptConfigCLI"]
        ),
        .plugin(
            name: "EncryptConfigPlugin",
            targets: ["EncryptConfigPlugin"]
        )
    ],
    targets: [
        .target(
            name: "EncryptConfigCore"
        ),
        .target(
            name: "EncryptConfigRuntime",
            dependencies: ["EncryptConfigCore"]
        ),
        .executableTarget(
            name: "EncryptConfigCLI",
            dependencies: ["EncryptConfigCore"]
        ),
        .plugin(
            name: "EncryptConfigPlugin",
            capability: .buildTool(),
            dependencies: ["EncryptConfigCLI"]
        ),
        .testTarget(
            name: "EncryptConfigCoreTests",
            dependencies: ["EncryptConfigCore"]
        ),
        .testTarget(
            name: "EncryptConfigRuntimeTests",
            dependencies: [
                "EncryptConfigRuntime",
                "EncryptConfigCore"
            ]
        )
    ]
)
