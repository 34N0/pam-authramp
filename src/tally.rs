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

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{settings::Settings, syslog_error, syslog_info, Actions};
use chrono::{DateTime, Duration, Utc};
use ini::Ini;
use pam::constants::PamResultCode;
use users::User;

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
    /// Calculates the delay based on the number of authentication failures and settings.
    /// Uses the authramp formula: delay=ramp_multiplier×(fails − free_tries)×ln(fails − free_tries)+base_delay_seconds
    ///
    /// # Arguments
    /// - `fails`: Number of authentication failures
    /// - `settings`: Settings for the authramp module
    ///
    /// # Returns
    /// Calculated delay as a floating-point number
    pub fn get_delay(&self, settings: &Settings) -> Duration {
        Duration::seconds(
            (settings.ramp_multiplier as f64
                * (self.failures_count as f64 - settings.free_tries as f64)
                * ((self.failures_count as f64 - settings.free_tries as f64).ln())
                + settings.base_delay_seconds as f64) as i64,
        )
    }

    /// Opens or creates the tally file based on the provided `Settings`.
    ///
    /// If the file exists, loads the values; if not, creates the file with default values.
    /// Updates the tally based on authentication actions, such as successful or failed attempts.
    ///
    /// # Arguments
    /// - `settings`: A reference to the `Settings` struct.
    ///
    /// # Returns
    /// A `Result` containing either the `Tally` struct or a `PAM_AUTH_ERR`.
    pub fn new_from_tally_file(settings: &Settings) -> Result<Self, PamResultCode> {
        let mut tally = Tally::default();
        let user = settings.get_user()?;

        let tally_file = settings.tally_dir.join(user.name());

        if tally_file.exists() {
            Self::load_tally_from_file(&mut tally, user, &tally_file, settings)?
        } else {
            Self::create_tally_file(&mut tally, &tally_file, settings)?
        };

        Ok(tally)
    }

    /// Loads tally information from an existing file.
    ///
    /// # Arguments
    /// - `tally_file`: A reference to the tally file `Path`.
    /// - `tally`: A mutable reference to the `Tally` struct.
    /// - `settings`: A reference to the `Settings` struct.
    ///
    /// # Returns
    /// A `Result` indicating success or a `PAM_SYSTEM_ERR` in case of errors.
    fn load_tally_from_file(
        tally: &mut Tally,
        user: &User,
        tally_file: &Path,
        settings: &Settings,
    ) -> Result<(), PamResultCode> {
        Ini::load_from_file(tally_file)
            .map_err(|e| {
                syslog_error!("PAM_SYSTEM_ERR: Error reading tally file: {}", e);
                PamResultCode::PAM_SYSTEM_ERR
            })
            .and_then(|i| {
                // If the "Fails" section exists, extract and set values
                if let Some(fails_section) = i.section(Some("Fails")) {
                    Some(fails_section)
    .map(|section| {

        tally.failures_count = section.get("count")
        .map(|count| count.parse())
        .transpose()
        .map_err(|_e| { PamResultCode::PAM_SYSTEM_ERR })?
        .unwrap_or_default();

        tally.failure_instant = section.get("instant")
        .map(|instant| instant.parse())
        .transpose().map_err(|_e| { PamResultCode::PAM_SYSTEM_ERR })?
        .unwrap_or_default();

        tally.unlock_instant = section.get("unlock_instant")
        .map(|unlock_instant| unlock_instant.parse())
        .transpose()
        .map_err(|_e| { PamResultCode::PAM_SYSTEM_ERR })?;

        Ok(())
    })
    .transpose()?;
                } else {
                    // If the section doesn't exist, return an error
                    syslog_error!("PAM_SYSTEM_ERR: Error reading tally file: [SETTINGS] section does not exist");
                    return Err(PamResultCode::PAM_SYSTEM_ERR);
                }

                Self::update_tally_from_section(tally, user, tally_file, settings)
            })
    }

    /// Updates tally information based on a section from the tally file.
    ///
    /// AUTHSUCC deteltes the tally
    /// AUTHERR increases the tally
    /// PREAUTH is ignored;
    ///
    /// # Arguments
    /// - `fails_section`: A reference to the "Fails" section of the INI file.
    /// - `tally`: A mutable reference to the `Tally` struct.
    /// - `settings`: A reference to the `Settings` struct.
    ///
    /// # Returns
    /// A `Result` indicating success or a `PAM_SYSTEM_ERR` in case of errors.
    fn update_tally_from_section(
        tally: &mut Tally,
        user: &User,
        tally_file: &Path,
        settings: &Settings,
    ) -> Result<(), PamResultCode> {
        // Handle specific actions based on settings.action
        match settings.get_action()? {
            Actions::PREAUTH => return Ok(()),
            Actions::AUTHSUCC => {
                // total failures for logging
                let total_failures = tally.failures_count;

                // If action is AUTHFAIL, update count
                tally.failures_count = 0;

                // Reset unlock_instant to None on AUTHSUCC
                tally.unlock_instant = None;

                // Write the updated values back to the file
                let mut i = Ini::new();
                i.with_section(Some("Fails"))
                    .set("count", tally.failures_count.to_string());

                i.write_to_file(tally_file).map_err(|e| {
                    syslog_error!("PAM_SYSTEM_ERR: Error reseting tally: {}", e);
                    PamResultCode::PAM_SYSTEM_ERR
                })?;

                // log account unlock
                if total_failures > 0 {
                    syslog_info!(
                        "PAM_SUCCESS: Clear tally ({} failures) for the {:?} account. Account is unlocked.",
                        total_failures,
                        user.name()
                    );
                }
            }
            Actions::AUTHFAIL => {
                // If action is AUTHFAIL, update count and instant
                tally.failures_count += 1;
                tally.failure_instant = Utc::now();

                let mut delay = tally.get_delay(settings);

                // Cap unlock_instant at 24 hours from now
                if delay > Duration::hours(24) {
                    delay = Duration::hours(24)
                }

                tally.unlock_instant = Some(tally.failure_instant + delay);

                // Write the updated values back to the file
                let mut i = Ini::new();
                i.with_section(Some("Fails"))
                    .set("count", tally.failures_count.to_string())
                    .set("instant", tally.failure_instant.to_string())
                    .set("unlock_instant", tally.unlock_instant.unwrap().to_string());

                i.write_to_file(tally_file).map_err(|e| {
                    syslog_error!("PAM_SYSTEM_ERR: Error writing tally file: {}", e);
                    PamResultCode::PAM_SYSTEM_ERR
                })?;

                if tally.failures_count > settings.free_tries {
                    // log account unlock

                    syslog_info!(
                    "PAM_AUTH_ERR: Added tally ({} failures) for the {:?} account. Account is locked until {}.",
                    tally.failures_count,
                    user.name(),
                    tally.unlock_instant.unwrap()
                );
                }
            }
        }
        Ok(())
    }

    /// Creates a new tally file with default values.
    ///
    /// # Arguments
    /// - `tally_file`: A reference to the tally file `Path`.
    /// - `tally`: A mutable reference to the `Tally` struct.
    /// - `settings`: A reference to the `Settings` struct.
    ///
    /// # Returns
    /// A `Result` indicating success or a `PAM_SYSTEM_ERR` in case of errors.
    fn create_tally_file(
        tally: &mut Tally,
        tally_file: &Path,
        _settings: &Settings,
    ) -> Result<(), PamResultCode> {
        fs::create_dir_all(tally_file.parent().unwrap()).map_err(|e| {
            syslog_error!("PAM_SYSTEM_ERR: Error creating tally file: {}", e);
            PamResultCode::PAM_SYSTEM_ERR
        })?;

        let mut ini = Ini::new();
        ini.with_section(Some("Fails"))
            .set("count", tally.failures_count.to_string())
            .set("instant", tally.failure_instant.to_string());

        // Write the INI file to disk
        ini.write_to_file(tally_file).map_err(|e| {
            syslog_error!("PAM_SYSTEM_ERR: Error writing tally file: {}", e);
            PamResultCode::PAM_SYSTEM_ERR
        })?;

        Ok(())
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
        let result = Tally::new_from_tally_file(&settings);

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
        let result = Tally::new_from_tally_file(&settings);

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
            pam_hook: String::from("test"),
        };

        let tally = Tally::new_from_tally_file(&settings).unwrap();

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
            pam_hook: String::from("test"),
        };

        let _tally = Tally::new_from_tally_file(&settings).unwrap();

        // Expect tally count to decrease
        let ini_content = fs::read_to_string(&tally_file_path).unwrap();
        assert!(ini_content.contains("count=0"), "Expected tally count = 0");
        assert!(!ini_content.contains("unlock_instant="));
    }
}
