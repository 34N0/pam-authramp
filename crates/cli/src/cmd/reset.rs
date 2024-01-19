use std::{fs, path::PathBuf};
use util::config::Config;

use crate::{ArCliError, ArCliResult};

pub fn user(user: &str) -> ArCliResult {
    let config = Config::load_file(None);

    let tally_path = config.tally_dir.join(user);

    delete_tally(&tally_path)
}

fn delete_tally(path: &PathBuf) -> ArCliResult {
    match fs::remove_file(path) {
        Ok(()) => Ok(Some(String::from("File successfully deleted"))),
        Err(e) => Err(ArCliError {
            message: format!("Error deleting file: {e}").to_string(),
        }),
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
        let result = delete_tally(&temp_tally_path);

        // Assert that the file is deleted successfully
        assert!(result.is_ok());
        assert!(!temp_tally_path.exists(), "Tally File not deleted!");
    }
}
