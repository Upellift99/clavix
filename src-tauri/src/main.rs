// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Ubuntu 24.04 ships WebKit2GTK 4.1 with the DMABUF renderer enabled
    // by default. That renderer needs the running user to be able to
    // allocate GBM buffers via /dev/dri, which means membership in the
    // `render` (or sometimes `video`) group. On a fresh install many
    // users are not — the failure is silent: WebKit logs a
    // `KMS: DRM_IOCTL_MODE_CREATE_DUMB failed: Permission denied`
    // line on stderr and the window paints blank. Users (and even
    // maintainers staring at .deb installs) reasonably read this as a
    // Tauri / SvelteKit / Clavix bug.
    //
    // Fall back to the non-DMABUF compositor by default. The CSS-only
    // UI Clavix renders (lists, forms, no animation, no canvas) is the
    // exact workload where the perf delta is invisible. Power users on
    // a system where DMABUF works can still opt back in by setting
    // WEBKIT_DISABLE_DMABUF_RENDERER=0 in the environment before
    // launching.
    //
    // Same family of issue as the CI flake we already mitigate with
    // WEBKIT_DISABLE_COMPOSITING_MODE in tests/e2e/wdio.conf.mjs.
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
            // SAFETY: single-threaded init code, runs before any other
            // thread can read env. Tauri's runtime is started by
            // clavix_lib::run() below.
            unsafe { std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1") };
        }
    }

    clavix_lib::run()
}
