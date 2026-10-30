use std::path::Path;

fn main() {
    let mut attributes = tauri_build::Attributes::new();

    // Windows (MSVC): Tauri's window stack imports TaskDialogIndirect, which
    // only comctl32 v6 exports, and a process gets v6 only through a
    // Common Controls manifest. tauri-build puts that manifest in the app
    // binary's resources and nowhere else, so a test binary that links the
    // window code (the `tauri::test` mock app in `legacy_app_dirs`) dies at
    // load with STATUS_ENTRYPOINT_NOT_FOUND before any test runs. Handing
    // the same manifest to the linker instead covers the app, the unit-test
    // binaries and the integration tests alike.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        attributes = attributes
            .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest());
        let manifest = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("windows-app-manifest.xml");
        println!("cargo:rerun-if-changed=windows-app-manifest.xml");
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    }

    tauri_build::try_build(attributes).expect("failed to run tauri-build");
}
