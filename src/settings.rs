//! # Settings Module
//!
//! The `settings` module is responsible for managing configuration settings related to the
//! authramp PAM module. It provides a structure `Settings` and functions to load configuration
//! from an INI file, build settings based on user input, and set default values.
//!
//! ## Overview
//!
//! The `Settings` structure represents the configuration settings for the authramp PAM module.
//! It includes fields such as `action`, `user`, `tally_dir`, `free_tries`, `base_delay_seconds`,
//! and `ramp_multiplier`.
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

use crate::{syslog_info, Actions};
use pam::constants::{PamFlag, PamResultCode};
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::path::PathBuf;

use users::User;

const DEFAULT_TALLY_DIR: &str = "/var/run/authramp";
const DEFAULT_CONFIG_FILE_PATH: &str = "/etc/security/authramp.conf";

// Settings struct represents the configuration loaded from default values, configuration file and parameters
#[derive(Debug)]
pub struct Settings {
    // Directory where tally information is stored.
    pub tally_dir: PathBuf,
    // Number of allowed free authentication attempts before applying delays.
    pub free_tries: i32,
    // Base delay applied to each authentication failure.
    pub base_delay_seconds: i32,
    // Multiplier for the delay calculation based on the number of failures.
    pub ramp_multiplier: i32,
    // PAM Hook
    pub pam_hook: String,
    // PAM action
    pub action: Option<Actions>,
    // PAM user
    pub user: Option<User>,
    // Even lock out root user
    pub even_deny_root: bool,
}

impl Default for Settings {
    /// Creates a default 'Settings' struct. Default configruation values are set here.
    fn default() -> Self {
        Settings {
            tally_dir: PathBuf::from(DEFAULT_TALLY_DIR),
            action: Some(Actions::AUTHSUCC),
            user: None,
            free_tries: 6,
            base_delay_seconds: 30,
            ramp_multiplier: 50,
            pam_hook: String::from("auth"),
            even_deny_root: false,
        }
    }
}

impl Settings {
    /// Constructs a `Settings` instance based on input parameters, including user
    /// information, PAM flags, and an optional configuration file path.
    ///
    /// # Arguments
    ///
    /// * `user`: An optional `User` instance representing the user associated with
    ///   the PAM session.
    /// * `args`: A vector of CStr references representing the PAM module arguments.
    /// * `_flags`: PAM flags indicating the context of the PAM operation (unused).
    /// * `config_file`: An optional `PathBuf` specifying the path to the INI file. If
    ///   not provided, the default configuration file path is used.
    ///
    /// # Returns
    ///
    /// A `Result` containing the constructed `Settings` instance or a `PamResultCode`
    /// indicating an error during the construction process.
    pub fn build(
        user: Option<User>,
        args: Vec<&CStr>,
        _flags: PamFlag,
        config_file: Option<PathBuf>,
        pam_hook: &str,
    ) -> Result<Settings, PamResultCode> {
        // Load INI file.
        let mut settings = Self::load_conf_file(config_file);

        // create possible action collection
        let action_map: HashMap<&str, Actions> = [
            ("preauth", Actions::PREAUTH),
            ("authsucc", Actions::AUTHSUCC),
            ("authfail", Actions::AUTHFAIL),
        ]
        .iter()
        .cloned()
        .collect();

        // map argument to action
        settings.action = args.iter().find_map(|&carg| {
            carg.to_str()
                .ok()
                .and_then(|arg| action_map.get(arg).cloned())
        });

        // set default action if none is provided
        settings.action.get_or_insert(Actions::AUTHSUCC);

        // get user
        settings.user = Some(user.ok_or(PamResultCode::PAM_SYSTEM_ERR)?);

        // pam hook
        settings.pam_hook = String::from(pam_hook);

        Ok(settings)
    }

    /// Gets the PAM action associated with the current settings.
    ///
    /// # Returns
    ///
    /// A `Result` containing the PAM action (`Actions`) if available, or a `PamResultCode`
    /// aborting Pam Authentication if the action is not present.
    pub fn get_action(&self) -> Result<Actions, PamResultCode> {
        self.action.ok_or(PamResultCode::PAM_ABORT)
    }

    /// Gets the PAM user associated with the current settings.
    ///
    /// # Returns
    ///
    /// A `Result` containing a reference to the PAM user (`&User`) if available, or a `PamResultCode`
    /// indicating a user_unknown error if the user is not present.
    pub fn get_user(&self) -> Result<&User, PamResultCode> {
        self.user.as_ref().ok_or_else(|| {
            syslog_info!("PAM_USER_UNKNOWN: Authentication failed because user is unknown",);
            PamResultCode::PAM_USER_UNKNOWN
        })
    }

    /// Loads configuration settings from an INI file, returning a `Settings` instance.
    ///
    /// # Arguments
    ///
    /// * `config_file`: An optional `PathBuf` specifying the path to the INI file. If
    ///   not provided, the default configuration file path is used.
    ///
    /// # Returns
    ///
    /// A `Settings` instance populated with values from the configuration file, or the
    /// default values if the file is not present or cannot be loaded.
    fn load_conf_file(config_file: Option<PathBuf>) -> Settings {
        // Read TOML file using the toml crate
        let content =
            fs::read_to_string(config_file.unwrap_or(PathBuf::from(DEFAULT_CONFIG_FILE_PATH))).ok();

        // Parse TOML content into a TomlTable
        let toml_table: Option<toml::value::Table> =
            content.and_then(|c| toml::de::from_str(&c).ok());

        // Extract the "Settings" section from the TOML table
        let settings = toml_table.and_then(|t| t.get("Settings").cloned());

        // Map the settings to the Settings struct
        settings
            .map(|s| Settings {
                tally_dir: s
                    .get("tally_dir")
                    .and_then(|val| val.as_str().map(PathBuf::from))
                    .unwrap_or_else(|| Settings::default().tally_dir),
                free_tries: s
                    .get("free_tries")
                    .and_then(|val| val.as_integer())
                    .map(|val| val as i32)
                    .unwrap_or_else(|| Settings::default().free_tries),
                base_delay_seconds: s
                    .get("base_delay_seconds")
                    .and_then(|val| val.as_integer())
                    .map(|val| val as i32)
                    .unwrap_or_else(|| Settings::default().base_delay_seconds),
                ramp_multiplier: s
                    .get("ramp_multiplier")
                    .and_then(|val| val.as_float())
                    .map(|val| val as i32)
                    .unwrap_or_else(|| Settings::default().ramp_multiplier),
                even_deny_root: s
                    .get("even_deny_root")
                    .and_then(|val| val.as_bool())
                    .unwrap_or_else(|| Settings::default().even_deny_root),
                ..Settings::default()
            })
            .unwrap_or_default()
    }
}

// Unit Tests
#[cfg(test)]
mod tests {
    extern crate tempdir;

    use self::tempdir::TempDir;
    use super::*;
    use std::ffi::CStr;
    use users::User;

    #[test]
    fn test_default_settings() {
        let default_settings = Settings::default();
        assert_eq!(default_settings.tally_dir, PathBuf::from(DEFAULT_TALLY_DIR));
        assert_eq!(default_settings.action, Some(Actions::AUTHSUCC));
        assert!(default_settings.user.is_none());
        assert_eq!(default_settings.free_tries, 6);
        assert_eq!(default_settings.base_delay_seconds, 30);
        assert_eq!(default_settings.ramp_multiplier, 50);
        assert!(!default_settings.even_deny_root);
    }

    #[test]
    fn test_build_settings_from_toml() {
        let temp_dir = TempDir::new("test_build_settings_from_toml").unwrap();
        let conf_file_path = temp_dir.path().join("config.conf");

        // Create a TOML file with settings
        let toml_content = r#"
        [Settings]
        tally_dir = "/tmp/tally_dir"
        free_tries = 10
        base_delay_seconds = 15
        ramp_multiplier = 20.0
        even_deny_root = true
    "#;
        std::fs::write(&conf_file_path, toml_content).unwrap();

        // Create PAM arguments
        let args = [CStr::from_bytes_with_nul("preauth\0".as_bytes()).unwrap()].to_vec();
        let flags: PamFlag = 0;

        // Build settings from TOML
        let result = Settings::build(
            Some(User::new(9999, "test_user", 9999)),
            args,
            flags,
            Some(conf_file_path.clone()),
            "test",
        );

        // Validate the result
        assert!(result.is_ok());
        let settings = result.unwrap();
        assert_eq!(settings.action, Some(Actions::PREAUTH));
        assert_eq!(settings.tally_dir, PathBuf::from("/tmp/tally_dir"));
        assert!(settings.user.is_some());
        assert_eq!(settings.user.unwrap().name(), "test_user");
        assert_eq!(settings.free_tries, 10);
        assert_eq!(settings.base_delay_seconds, 15);
        assert_eq!(settings.ramp_multiplier, 20);
        assert!(settings.even_deny_root);
    }

    #[test]
    fn test_build_settings_missing_action() {
        let args = vec![];
        let flags: PamFlag = 0;
        let result = Settings::build(
            Some(User::new(9999, "test_user", 9999)),
            args,
            flags,
            None,
            "test",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_settings_from_toml_commented_out() {
        let temp_dir = TempDir::new("test_build_settings_from_toml").unwrap();
        let conf_file_path = temp_dir.path().join("config.conf");

        // Create a TOML file with settings
        let toml_content = r#"
        [Settings]
        # tally_dir = "/tmp/tally_dir"
        # free_tries = 10
        # base_delay_seconds = 15
        # ramp_multiplier = 20.0
        # even_deny_root = true
    "#;
        std::fs::write(&conf_file_path, toml_content).unwrap();

        // Create PAM arguments
        let args = [CStr::from_bytes_with_nul("preauth\0".as_bytes()).unwrap()].to_vec();
        let flags: PamFlag = 0;

        // Build settings from TOML
        let result = Settings::build(
            Some(User::new(9999, "test_user", 9999)),
            args,
            flags,
            Some(conf_file_path.clone()),
            "test",
        );

        // Validate the result
        assert!(result.is_ok());
        let settings = result.unwrap();
        // println!("{:?}", settings);
        assert_eq!(settings.action, Some(Actions::PREAUTH));
        assert_eq!(settings.tally_dir, PathBuf::from(DEFAULT_TALLY_DIR));
        assert_eq!(settings.free_tries, 6);
        assert_eq!(settings.base_delay_seconds, 30);
        assert_eq!(settings.ramp_multiplier, 50);
        assert!(!settings.even_deny_root);
    }

    #[test]
    fn test_build_settings_missing_user() {
        let args = [CStr::from_bytes_with_nul("preauth\0".as_bytes()).unwrap()].to_vec();
        let flags: PamFlag = 0;
        let result = Settings::build(None, args, flags, None, "test");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), PamResultCode::PAM_SYSTEM_ERR);
    }
}
