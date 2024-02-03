//! # Settings Module
//!
//! The `settings` module is responsible for managing configuration settings related to the
//! authramp PAM module.
//!
//! ## Overview
//!
//! The `Settings` structure represents the configuration settings for the authramp PAM module.
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

use crate::actions::Actions;
use crate::config::Config;
use pam::{PamFlag, PamResultCode};
use std::collections::HashMap;
use std::ffi::CStr;

use uzers::User;

// Settings struct represents the configuration loaded from default values, configuration file and parameters
#[derive(Debug)]
pub struct Settings<'a> {
    // PAM Hook
    pub pam_hook: &'a str,
    // PAM action
    pub action: Option<Actions>,
    // PAM user
    pub user: Option<User>,
    // Config
    pub config: Config,
}

impl Default for Settings<'_> {
    /// Creates a default 'Settings' struct. Default configruation values are set here.
    fn default() -> Self {
        Settings {
            action: Some(Actions::AUTHSUCC),
            user: None,
            pam_hook: "auth",
            config: Config::load_file(None),
        }
    }
}

impl Settings<'_> {
    /// Constructs a `Settings` instance based on input parameters, including user
    /// information, PAM flags, and an optional configuration file path.
    ///
    /// # Arguments
    ///
    /// * `user`: An optional `User` instance representing the user associated with
    ///   the PAM session.
    /// * `args`: A vector of `CStr` references representing the PAM module arguments.
    /// * `_flags`: PAM flags indicating the context of the PAM operation (unused).
    /// * `config_file`: An optional `PathBuf` specifying the path to the TOML file. If
    ///   not provided, the default configuration file path is used.
    ///
    /// # Returns
    ///
    /// A `Result` containing the constructed `Settings` instance or a `PamResultCode`
    /// indicating an error during the construction process.
    ///
    /// # Errors
    ///
    /// Returns a `PamResultCode` error.
    pub fn build<'a>(
        user: Option<User>,
        args: &[&CStr],
        _flags: PamFlag,
        pam_hook: &'a str,
    ) -> Result<Settings<'a>, PamResultCode> {
        // Load TOML file.
        let mut settings = Settings::default();

        // create possible action collection
        let action_map: HashMap<&str, Actions> = [
            ("preauth", Actions::PREAUTH),
            ("authsucc", Actions::AUTHSUCC),
            ("authfail", Actions::AUTHFAIL),
        ]
        .iter()
        .copied()
        .collect();

        // map argument to action
        settings.action = args.iter().find_map(|&carg| {
            carg.to_str()
                .ok()
                .and_then(|arg| action_map.get(arg).copied())
        });

        // set default action if none is provided
        settings.action.get_or_insert(Actions::AUTHSUCC);

        // get user
        settings.user = Some(user.ok_or(PamResultCode::PAM_USER_UNKNOWN)?);

        // pam hook
        settings.pam_hook = pam_hook;

        Ok(settings)
    }

    /// Gets the PAM action associated with the current settings.
    ///
    /// # Returns
    ///
    /// A `Result` containing the PAM action (`Actions`) if available, or a `PamResultCode`
    /// aborting Pam Authentication if the action is not present.
    ///
    /// # Errors
    ///
    /// Returns a `PamResultCode` error.
    pub fn get_action(&self) -> Result<Actions, PamResultCode> {
        self.action.ok_or(PamResultCode::PAM_ABORT)
    }

    /// Gets the PAM user associated with the current settings.
    ///
    /// # Returns
    ///
    /// A `Result` containing a reference to the PAM user (`&User`) if available, or a `PamResultCode`
    /// indicating a `user_unknown` error if the user is not present.
    ///     
    /// # Errors
    ///
    /// Returns a `PamResultCode` error.
    pub fn get_user(&self) -> Result<&User, PamResultCode> {
        self.user.as_ref().ok_or_else(|| {
            // log_info!("PAM_USER_UNKNOWN: Authentication failed because user is unknown",);
            PamResultCode::PAM_USER_UNKNOWN
        })
    }
}

// Unit Tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use uzers::User;

    #[test]
    fn test_default_settings() {
        let default_settings = Settings::default();
        assert_eq!(default_settings.action, Some(Actions::AUTHSUCC));
        assert!(default_settings.user.is_none());
    }

    #[test]
    fn test_build_settings_missing_action() {
        let args = vec![];
        let flags: PamFlag = 0;
        let result = Settings::build(
            Some(User::new(9999, "test_user", 9999)),
            &args,
            flags,
            "test",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_settings_missing_user() {
        let args = [CStr::from_bytes_with_nul("preauth\0".as_bytes()).unwrap()].to_vec();
        let flags: PamFlag = 0;
        let result = Settings::build(None, &args, flags, "test");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), PamResultCode::PAM_USER_UNKNOWN);
    }
}
