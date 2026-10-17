// Sidetone desktop: starts the embedded local server (analysis, AI proxy,
// softphone engine) on a random loopback port and opens it in a native window.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use tauri::{WebviewUrl, WebviewWindowBuilder};

fn main() {
    let save: sidetone_cli::serve::SaveHook = Arc::new(|name: &str, data: &[u8]| {
        let path = rfd::FileDialog::new().set_file_name(name).save_file();
        match path {
            Some(p) => {
                std::fs::write(&p, data)?;
                Ok(Some(p))
            }
            None => Ok(None),
        }
    });
    let (url, _server) = sidetone_cli::serve::spawn("127.0.0.1:0", None, true, Some(save))
        .expect("start local server");

    tauri::Builder::default()
        .setup(move |app| {
            let target: tauri::Url = url.parse()?;
            WebviewWindowBuilder::new(app, "main", WebviewUrl::External(target))
                .title("Sidetone")
                .inner_size(1400.0, 880.0)
                .min_inner_size(900.0, 600.0)
                .build()?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Sidetone")
        .run(|_app, event| {
            // Hang up and unregister before the process goes away.
            if let tauri::RunEvent::Exit = event {
                sidetone_cli::phone::shutdown();
            }
        });
}
