mod api;
mod error;
mod models;

use api::VaultwardenClient;
use error::Result;
use models::Prelogin;

#[tauri::command]
async fn prelogin(server_url: String, email: String) -> Result<Prelogin> {
    let client = VaultwardenClient::new(&server_url)?;
    client.prelogin(&email).await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![prelogin])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
