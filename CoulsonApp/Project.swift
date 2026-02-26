import ProjectDescription

let project = Project(
    name: "Coulson",
    packages: [
        .remote(url: "https://github.com/sparkle-project/Sparkle", requirement: .upToNextMajor(from: "2.6.0")),
    ],
    targets: [
        .target(
            name: "CoulsonApp",
            destinations: .macOS,
            product: .app,
            productName: "Coulson",
            bundleId: "ac.hola.coulson",
            infoPlist: .extendingDefault(with: [
                "CFBundleName": "Coulson",
                "CFBundleIconFile": "AppIcon",
                "CFBundleShortVersionString": "$(MARKETING_VERSION)",
                "CFBundleVersion": "$(CURRENT_PROJECT_VERSION)",
                "LSUIElement": true,
                "NSHighResolutionCapable": true,
                "CFBundleDocumentTypes": .array([
                    .dictionary([
                        "CFBundleTypeName": .string("Folder"),
                        "CFBundleTypeRole": .string("Viewer"),
                        "LSItemContentTypes": .array([.string("public.folder")]),
                        "LSHandlerRank": .string("Alternate"),
                    ]),
                ]),
                "SUFeedURL": "https://coulson.hola.ac/stable/appcast.xml",
                "SUPublicEDKey": "PjUKuY0BMBoamFyfAYOGYPvRk2JVWa3uYsaZyR7ivnQ=",
            ]),
            sources: ["Sources/**/*.swift"],
            resources: [
                "Sources/Resources/MenuBarIcon.png",
                "Sources/Resources/MenuBarIcon@2x.png",
                "Sources/Resources/AppIcon.png",
            ],
            scripts: [
                .post(
                    script: """
                    DAEMON_BIN="${PROJECT_DIR}/../target/release/coulson"
                    if [ -f "$DAEMON_BIN" ]; then
                        mkdir -p "${BUILT_PRODUCTS_DIR}/${CONTENTS_FOLDER_PATH}/Resources"
                        cp "$DAEMON_BIN" "${BUILT_PRODUCTS_DIR}/${CONTENTS_FOLDER_PATH}/Resources/coulson"
                        chmod +x "${BUILT_PRODUCTS_DIR}/${CONTENTS_FOLDER_PATH}/Resources/coulson"
                    else
                        echo "warning: Rust daemon not found at $DAEMON_BIN"
                    fi
                    """,
                    name: "Copy Rust Daemon",
                    basedOnDependencyAnalysis: false
                ),
            ],
            dependencies: [
                .package(product: "Sparkle"),
            ],
            settings: .settings(
                base: [
                    "MACOSX_DEPLOYMENT_TARGET": "13.0",
                    "MARKETING_VERSION": "0.2.1",
                    "CURRENT_PROJECT_VERSION": "1",
                ]
            )
        ),
    ]
)
