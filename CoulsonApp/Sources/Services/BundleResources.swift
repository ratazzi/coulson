import Foundation

extension Bundle {
    /// Resolves the resource bundle for both SPM dev mode and .app production mode.
    ///
    /// - .app bundle: `Bundle.main` searches `Contents/Resources/` where build-app.sh puts the files.
    /// - SPM `swift run`: `Bundle.module` points to the SPM-generated resource bundle.
    static var appResources: Bundle {
        // In production .app, Bundle.main has our resources in Contents/Resources/
        if Bundle.main.bundleIdentifier == "ac.hola.coulson" {
            return Bundle.main
        }
        return Bundle.module
    }
}
