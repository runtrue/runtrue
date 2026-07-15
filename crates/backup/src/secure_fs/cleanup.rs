use super::directories::PreparedDirectory;
use std::{fs, path::Path};

pub(crate) fn cleanup_directory(path: &Path, prepared: &PreparedDirectory) {
    if prepared.created {
        let _ = fs::remove_dir_all(path);
        return;
    }
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let child = entry.path();
            match fs::symlink_metadata(&child) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                    let _ = fs::remove_dir_all(child);
                }
                Ok(_) => {
                    let _ = fs::remove_file(child);
                }
                Err(_) => {}
            }
        }
    }
}
