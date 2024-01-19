use colored::Colorize;
use std::{fs, path::PathBuf};
use util::config::Config;

use crate::{ArCliError, ArCliInfo, ArCliResult as Acr, ArCliSuccess};

pub fn user(user: &str) -> Acr {
    let config = Config::load_file(None);

    let tally_path = config.tally_dir.join(user);

    delete_tally(&tally_path, user)
}

fn delete_tally(path: &PathBuf, user: &str) -> Acr {
    match fs::remove_file(path) {
        Ok(()) => Acr::Success(Some(ArCliSuccess {
            message: format!("tally reset for user: '{}'", user.yellow()),
        })),
        Err(e) => {
            if e.kind().eq(&std::io::ErrorKind::NotFound) {
                Acr::Info(ArCliInfo {
                    message: format!("No tally found for user: '{}'", user.yellow()),
                })
            } else {
                Acr::Error(ArCliError {
                    message: format!("{e}").to_string(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn test_delete_tally() {
        // Create a temporary directory for testing
        let temp_dir =
            TempDir::new("test_delete_tally").expect("Failed to create temporary directory");

        // Create a temporary file within the temporary directory
        let temp_tally_path = temp_dir.path().join("test_tally");
        fs::write(&temp_tally_path, "test tally").expect("Failed to create temporary file");

        // Load the Config into the reset_user function
        let _result = delete_tally(&temp_tally_path, "test");

        // Assert that the file is deleted successfully
        assert!(!temp_tally_path.exists(), "Tally File not deleted!");
    }
}
