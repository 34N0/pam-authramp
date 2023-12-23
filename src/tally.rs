//! # Tally Module
//!
//! The `tally` module manages the account lockout status, including the number of authentication
//! failures, the timestamp of the last failure, and the unlock time. It provides functionality to open
//! and update the tally based on authentication actions performed.
//!
//! ## Overview
//!
//! The `Tally` struct represents the account lockout information, and the module provides
//! functionality to interact with this information, updating it based on authentication results.
//!
//! ## Tally Structure
//!
//! The `Tally` struct has the following fields:
//!
//! - `tally_file`: An optional `PathBuf` representing the path to the file storing tally information.
//! - `failures_count`: An integer representing the number of authentication failures.
//! - `failure_instant`: A `DateTime<Utc>` representing the timestamp of the last authentication failure.
//! - `unlock_instant`: An optional `DateTime<Utc>` representing the time when the account will be unlocked.
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

use std::{fs, path::PathBuf};

use crate::{settings::Settings, Actions};
use chrono::{DateTime, Duration, Utc};
use ini::Ini;
use pam::constants::PamResultCode;

/// The `Tally` struct represents the account lockout information, including
/// the number of authentication failures and the timestamp of the last failure.
#[derive(Debug, PartialEq)]
pub struct Tally {
    /// An optional `PathBuf` representing the path to the file storing tally information.
    pub tally_file: Option<PathBuf>,
    /// An integer representing the number of authentication failures.
    pub failures_count: i32,
    /// A `DateTime<Utc>` representing the timestamp of the last authentication failure.
    pub failure_instant: DateTime<Utc>,
    /// An optional `DateTime<Utc>` representing the time when the account will be unlocked.
    pub unlock_instant: Option<DateTime<Utc>>,
}

impl Default for Tally {
    /// Creates a default `Tally` instance with zero failures and the current timestamp.
    fn default() -> Self {
        Tally {
            tally_file: None,
            failures_count: 0,
            failure_instant: Utc::now(),
            unlock_instant: None,
        }
    }
}

impl Tally {
    /// Opens or creates the tally file based on the provided `Settings`.
    ///
    /// If the file exists, loads the values; if not, creates the file with default values.
    /// Updates the tally based on authentication actions, such as successful or failed attempts.
    ///
    /// # Arguments
    /// - settings: Settings struct
    ///
    /// # Returns
    /// Tally struct or PAM_AUTH_ERR
    pub fn open(settings: &Settings) -> Result<Self, PamResultCode> {
        let mut tally = Tally::default();
        let user = settings.user.as_ref().ok_or(PamResultCode::PAM_AUTH_ERR)?;
        let tally_file = settings.tally_dir.join(user.name());

        // Check if the file exists
        let result = if tally_file.exists() {
            // If the file exists, attempt to load values from it
            Ini::load_from_file(&tally_file)
                .map_err(|_| PamResultCode::PAM_SYSTEM_ERR)
                .and_then(|i| {
                    // If the "Fails" section exists, extract and set values
                    if let Some(fails_section) = i.section(Some("Fails")) {
                        if let Some(count) = fails_section.get("count") {
                            tally.failures_count = count.parse().unwrap_or(0);
                        }

                        if let Some(instant) = fails_section.get("instant") {
                            tally.failure_instant = instant.parse().unwrap_or_default();
                        }

                        if let Some(unlock_instant) = fails_section.get("unlock_instant") {
                            tally.unlock_instant = Some(unlock_instant.parse().unwrap_or_default());
                        }

                        // Handle specific actions based on settings.action
                        match settings.action {
                            Some(Actions::AUTHSUCC) => {
                                // If action is AUTHFAIL, update count
                                tally.failures_count = 0;

                                // Reset unlock_instant to None on AUTHSUCC
                                tally.unlock_instant = None;

                                // Write the updated values back to the file
                                let mut i = Ini::new();
                                i.with_section(Some("Fails"))
                                    .set("count", tally.failures_count.to_string());

                                i.write_to_file(&tally_file)
                                    .map_err(|_| PamResultCode::PAM_SYSTEM_ERR)?;
                            }
                            Some(Actions::AUTHFAIL) => {
                                // If action is AUTHFAIL, update count and instant
                                tally.failures_count += 1;
                                tally.failure_instant = Utc::now();
                                // Set unlock_instant to 24 hours from now
                                tally.unlock_instant =
                                    Some(tally.failure_instant + Duration::hours(24));
                                // Write the updated values back to the file
                                let mut i = Ini::new();
                                i.with_section(Some("Fails"))
                                    .set("count", tally.failures_count.to_string())
                                    .set("instant", tally.failure_instant.to_string())
                                    .set(
                                        "unlock_instant",
                                        tally.unlock_instant.unwrap().to_string(),
                                    );

                                i.write_to_file(&tally_file)
                                    .map_err(|_| PamResultCode::PAM_SYSTEM_ERR)?;
                            }
                            _ => {}
                        }

                        Ok(())
                    } else {
                        // If the section doesn't exist, return an error
                        Err(PamResultCode::PAM_SYSTEM_ERR)
                    }
                })
        } else {
            // If the file doesn't exist, create it
            fs::create_dir_all(tally_file.parent().unwrap())
                .map_err(|_| PamResultCode::PAM_SYSTEM_ERR)?;

            let mut i = Ini::new();
            i.with_section(Some("Fails"))
                .set("count", tally.failures_count.to_string())
                .set("instant", tally.failure_instant.to_string());

            // Write the INI file to disk
            i.write_to_file(&tally_file)
                .map_err(|_| PamResultCode::PAM_SYSTEM_ERR)?;

            Ok(())
        };

        // Map the final result to the Tally structure
        result.map(|_| tally)
    }
}

// Unit Tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempdir::TempDir;
    use users::User;

    #[test]
    fn test_open_existing_tally_file() {
        // Create a temporary directory
        let temp_dir = TempDir::new("test_open_existing_tally_file").unwrap();
        let tally_file_path = temp_dir.path().join("test_user_a");

        // Create an existing INI file
        let mut i = Ini::new();
        i.with_section(Some("Fails"))
            .set("count", "42")
            .set("instant", "2023-01-01T00:00:00Z")
            .set("unlock_instant", "2023-01-02T00:00:00Z");

        i.write_to_file(tally_file_path).unwrap();

        // Create settings and call open
        let settings = Settings {
            user: Some(User::new(9999, "test_user_a", 9999)),
            tally_dir: temp_dir.path().to_path_buf(),
            action: Some(Actions::PREAUTH),
            ..Default::default()
        };

        // Test: Open existing tally file
        let result = Tally::open(&settings);

        // Check if the Tally struct is created with expected values
        assert!(result.is_ok());
        let tally = result.unwrap();
        assert_eq!(tally.failures_count, 42);
        assert_eq!(
            tally.failure_instant,
            DateTime::parse_from_rfc3339("2023-01-01T00:00:00Z").unwrap()
        );
        assert_eq!(
            tally.unlock_instant.unwrap(),
            DateTime::parse_from_rfc3339("2023-01-02T00:00:00Z").unwrap()
        );
    }

    #[test]
    fn test_open_nonexistent_tally_file() {
        // Create a temporary directory
        let temp_dir = TempDir::new("test_open_nonexistent_tally_file").unwrap();
        let tally_file_path = temp_dir.path().join("test_user_b");

        // Create settings and call open
        let settings = Settings {
            user: Some(User::new(9999, "test_user_b", 9999)),
            tally_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        // Test: Open nonexistent tally file
        let result = Tally::open(&settings);

        // Check if the Tally struct is created with default values
        assert!(result.is_ok());
        let tally = result.unwrap();
        assert_eq!(tally.failures_count, 0);
        assert!(tally.unlock_instant.is_none());

        // Check if the INI file has been created with default values
        let ini_content = fs::read_to_string(tally_file_path).unwrap();
        assert!(ini_content.contains("[Fails]"));
        assert!(ini_content.contains("count=0"));
        assert!(!ini_content.contains("unlock_instant="));
    }

    #[test]
    fn test_open_auth_fail_updates_values() {
        // Create a temporary directory
        let temp_dir = TempDir::new("test_open_auth_fail_updates_values").unwrap();
        let tally_file_path = temp_dir.path().join("test_user_c");

        // Create an existing INI file with some initial values
        let mut i = Ini::new();
        i.with_section(Some("Fails"))
            .set("count", "2")
            .set("instant", "2023-01-01T00:00:00Z")
            .set("unlock_instant", "2023-01-02T00:00:00Z");
        i.write_to_file(&tally_file_path).unwrap();

        // Create settings and call open with AUTHFAIL action
        let settings = Settings {
            user: Some(User::new(9999, "test_user_c", 9999)),
            tally_dir: temp_dir.path().to_path_buf(),
            action: Some(Actions::AUTHFAIL),
            free_tries: 6,
            ramp_multiplier: 50,
            base_delay_seconds: 30,
        };

        let tally = Tally::open(&settings).unwrap();

        // Check if the values are updated on AUTHFAIL
        assert_eq!(tally.failures_count, 3); // Assuming you increment the count
                                             // Also, assert that the instant is updated to the current time
        assert!(tally.unlock_instant.is_some());
        // Optionally, you can assert that the file is updated
        let ini_content = fs::read_to_string(&tally_file_path).unwrap();
        assert!(ini_content.contains("count=3"));
        // Also, assert the instant and unlock_instant values in the INI file

        // Additional assertions as needed
    }

    #[test]
    fn test_open_auth_succ_resets_tally() {
        // Create a temporary directory
        let temp_dir = TempDir::new("test_open_auth_succ_deletes_file").unwrap();
        let tally_file_path = temp_dir.path().join("test_user_d");

        // Create an existing INI file
        let mut i = Ini::new();
        i.with_section(Some("Fails"))
            .set("count", "2")
            .set("instant", "2023-01-01T00:00:00Z")
            .set("unlock_instant", "2023-01-02T00:00:00Z");
        i.write_to_file(&tally_file_path).unwrap();

        // Create settings and call open with AUTHSUCC action
        let settings = Settings {
            user: Some(User::new(9999, "test_user_d", 9999)),
            tally_dir: temp_dir.path().to_path_buf(),
            action: Some(Actions::AUTHSUCC),
            free_tries: 6,
            ramp_multiplier: 50,
            base_delay_seconds: 30,
        };

        let _tally = Tally::open(&settings).unwrap();

        // Expect tally count to decrease
        let ini_content = fs::read_to_string(&tally_file_path).unwrap();
        assert!(ini_content.contains("count=0"), "Expected tally count = 0");
        assert!(!ini_content.contains("unlock_instant="));
    }
}
