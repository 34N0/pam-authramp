//! # Reset Module
//!
//! The `reset` module provides functionality to reset the tally information for a user.
//! It is used in the context of the `sm_authenticate` PAM hook when the `reset` command is specified.
//! The tally information is stored in a file, and this module allows resetting the tally for a specific user.
//!
//! ## License
//!
//! pam-authramp
//! Copyright (C) 2023 github.com/34N0
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU General Public License as published by
//! the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//! GNU General Public License for more details.
//!
//! You should have received a copy of the GNU General Public License
//! along with this program.  If not, see <http://www.gnu.org/licenses/>.

use colored::Colorize;
use std::{fs, path::PathBuf};
use util::config::Config;

use crate::{ArCliError, ArCliInfo, ArCliResult as Acr, ArCliSuccess};

/// Resets the tally information for a specific user.
///
/// The function reads the configuration, constructs the path to the tally file for the given user,
/// and attempts to delete the tally file. It returns a result indicating the success or failure of the operation.
///
/// # Arguments
///
/// - `user`: The username for which the tally information should be reset.
///
/// # Returns
///
/// A `Result` representing the outcome of the operation.
///
/// - If successful, returns `ArCliResult::Success` with an optional `ArCliSuccess` containing a success message.
/// - If the tally file does not exist, returns `ArCliResult::Info` with an `ArCliInfo` containing an informational message.
/// - If an error occurs during the file deletion, returns `ArCliResult::Error` with an `ArCliError` containing the error message.
pub fn user(user: &str) -> Acr {
    let config = Config::load_file(None);

    let tally_path = config.tally_dir.join(user);

    delete_tally(&tally_path, user)
}

/// Deletes the tally file for a specific user.
///
/// The function attempts to remove the tally file specified by the provided path.
/// It returns a result indicating the success or failure of the operation.
///
/// # Arguments
///
/// - `path`: The path to the tally file.
/// - `user`: The username associated with the tally file.
///
/// # Returns
///
/// A `Result` representing the outcome of the operation.
///
/// - If successful, returns `ArCliResult::Success` with an optional `ArCliSuccess` containing a success message.
/// - If the tally file does not exist, returns `ArCliResult::Info` with an `ArCliInfo` containing an informational message.
/// - If an error occurs during the file deletion, returns `ArCliResult::Error` with an `ArCliError` containing the error message.
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
