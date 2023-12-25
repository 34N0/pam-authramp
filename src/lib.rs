//! # AuthRamp PAM Module
//!
//! The AuthRamp PAM (Pluggable Authentication Modules) module provides an account lockout mechanism
//! based on the number of authentication failures. It calculates a dynamic delay for subsequent
//! authentication attempts, increasing the delay with each failure to mitigate brute force attacks.
//!
//! ## Usage
//!
//! To use the AuthRamp PAM module, integrate it with the PAM system by configuring the `/etc/pam.d/`
//! configuration files for the desired PAM-aware services. This module is designed for the
//! `sm_authenticate` and `acct_mgmt` hooks.
//!
//! ## Configuration
//!
//! The behavior of the AuthRamp module is configurable through an INI file located at
//! `/etc/security/authramp.conf` by default. The configuration file can be customized with settings
//! such as the tally directory, free tries threshold, base delay, and multiplier.
//!
//! ```ini
//! [Settings]
//! tally_dir = /var/run/authramp
//! free_tries = 6
//! base_delay_seconds = 30
//! ramp_multiplier = 1.5
//! ```
//!
//! - `tally_dir`: Directory where tally information is stored.
//! - `free_tries`: Number of allowed free authentication attempts before applying delays.
//! - `base_delay_seconds`: Base delay applied to each authentication failure.
//! - `ramp_multiplier`: Multiplier for the delay calculation based on the number of failures.
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

mod settings;
mod tally;
mod utils;

extern crate chrono;
extern crate ini;
extern crate once_cell;
extern crate pam;
extern crate tempdir;
extern crate users;

use chrono::{Duration, Utc};
use pam::constants::{PamFlag, PamResultCode, PAM_ERROR_MSG};
use pam::conv::Conv;
use pam::module::{PamHandle, PamHooks};
use pam::pam_try;
use settings::Settings;
use std::cmp::min;
use std::ffi::CStr;

use std::thread::sleep;
use tally::Tally;
use users::get_user_by_name;

// Action argument defines position in PAM stack
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum Actions {
    PREAUTH,
    AUTHSUCC,
    #[default]
    AUTHFAIL,
}

/// Initializes the authramp module by setting up user information and loading settings.
/// Calls the provided pam_hook function with the initialized variables.
///
/// # Arguments
/// - `pamh`: PamHandle instance for interacting with PAM
/// - `_args`: PAM arguments provided during authentication
/// - `_flags`: PAM flags indicating the context of the PAM operation
/// - `pam_hook`: Function to be called with the initialized variables
///
/// # Returns
/// Result from the pam_hook function or PAM error code if initialization fails
fn init_authramp<F, R>(
    pamh: &mut PamHandle,
    _args: Vec<&CStr>,
    _flags: PamFlag,
    pam_hook_desc: &str,
    pam_hook: F,
) -> Result<R, PamResultCode>
where
    F: FnOnce(&mut PamHandle, &Settings, &Tally) -> Result<R, PamResultCode>,
{
    // Try to get PAM user
    let user = get_user_by_name(pam_try!(
        &pamh.get_user(None),
        Err(PamResultCode::PAM_AUTH_ERR)
    ));

    // Read configuration file
    let settings = Settings::build(user.clone(), _args, _flags, None, pam_hook_desc)?;

    utils::syslog::init_log(pamh, &settings)?;

    // Get and Set tally
    let tally = Tally::open(&settings)?;

    pam_hook(pamh, &settings, &tally)
}

/// Formats a Duration into a human-readable string representation.
/// The format includes hours, minutes, and seconds, excluding zero values.
///
/// # Arguments
/// - `remaining_time`: Duration representing the remaining time
///
/// # Returns
/// Formatted string indicating the remaining time
fn format_remaining_time(remaining_time: Duration) -> String {
    let mut formatted_time = String::new();

    if remaining_time.num_hours() > 0 {
        formatted_time.push_str(&format!("{} hours ", remaining_time.num_hours()));
    }

    if remaining_time.num_minutes() > 0 {
        formatted_time.push_str(&format!("{} minutes ", remaining_time.num_minutes() % 60));
    }

    formatted_time.push_str(&format!("{} seconds", remaining_time.num_seconds() % 60));

    formatted_time
}

/// Handles the account lockout mechanism based on the number of failures and settings.
/// If the account is locked, it sends periodic messages to the user until the account is unlocked.
///
/// # Arguments
/// - `pamh`: PamHandle instance for interacting with PAM
/// - `settings`: Settings for the authramp module
/// - `tally`: Tally information containing failure count and timestamps
///
/// # Returns
/// PAM_SUCCESS if the account is successfully unlocked, PAM_AUTH_ERR otherwise
fn bounce_auth(pamh: &mut PamHandle, settings: &Settings, tally: &Tally) -> PamResultCode {
    if tally.failures_count > settings.free_tries {
        if let Ok(Some(conv)) = pamh.get_item::<Conv>() {
            let delay = tally.get_delay(settings);

            // Calculate the time when the account will be unlocked
            let unlock_instant = tally
                .unlock_instant
                .unwrap_or(tally.failure_instant + delay);

            syslog_info!(
                "PAM_AUTH_ERR: Account {:?} is getting bounced. Account still locked until {}",
                settings.user.as_ref().unwrap().name(),
                unlock_instant,
            );

            while Utc::now() < unlock_instant {
                // Calculate remaining time until unlock
                let remaining_time = unlock_instant - Utc::now();

                // Cap remaining time at 24 hours
                let capped_remaining_time = min(remaining_time, Duration::hours(24));

                // Send a message to the conversation function
                let _ = conv.send(
                    PAM_ERROR_MSG,
                    &format!(
                        "Account locked! Unlocking in {}.",
                        format_remaining_time(capped_remaining_time)
                    ),
                );

                // Wait for one second
                sleep(std::time::Duration::from_secs(1));
            }

            // Account is now unlocked, continue with PAM_SUCCESS
            return PamResultCode::PAM_SUCCESS;
        }
    }

    // Account is not locked or an error occurred, return PAM_AUTH_ERR
    PamResultCode::PAM_AUTH_ERR
}
pub struct Pamauthramp;

pam::pam_hooks!(Pamauthramp);
impl PamHooks for Pamauthramp {
    /// Handles the `sm_authenticate` PAM hook, which is invoked during the authentication process.
    ///
    /// This function initializes the AuthRamp module by setting up user information and loading settings.
    ///
    /// This can be called with the PREAUTH action argument:
    /// auth        required                                     libpam_authramp.so preauth
    /// It then checks if an account is locked. And if that is true it bounces the auth.
    ///
    /// It can also be called with the AUTHFAIL action argument:
    /// auth        [default=die]                                libpam_authramp.so authfail
    /// It then locks the account and increments the delay.
    ///
    /// # Arguments
    /// - `pamh`: PamHandle instance for interacting with PAM
    /// - `args`: PAM arguments provided during authentication
    /// - `flags`: PAM flags indicating the context of the PAM operation
    ///
    /// # Returns
    /// PAM_SUCCESS OR PAM_AUTH_ERR
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        init_authramp(pamh, args, flags, "auth", |pamh, settings, tally| {
            // match action parameter
            match settings.action {
                Some(Actions::PREAUTH) => {
                    // if account is locked then bounce
                    if tally.failures_count > settings.free_tries {
                        Err(bounce_auth(pamh, settings, tally))
                    } else {
                        Ok(PamResultCode::PAM_SUCCESS)
                    }
                }
                // bounce if called with authfail
                Some(Actions::AUTHFAIL) => Err(bounce_auth(pamh, settings, tally)),
                None | Some(Actions::AUTHSUCC) => Err(PamResultCode::PAM_AUTH_ERR),
            }
        })
        .unwrap_or(PamResultCode::PAM_SUCCESS)
    }

    /// Handles the `acct_mgmt` PAM hook, which is invoked during the account management process.
    ///
    /// This function initializes the AuthRamp module by setting up user information and loading settings.
    ///
    /// This hook is only called on sucessful authentication and clears the tally to unlock the account:
    /// account     required                                     libpam_authramp.so
    ///
    /// # Arguments
    /// - `pamh`: PamHandle instance for interacting with PAM
    /// - `args`: PAM arguments provided during account management
    /// - `flags`: PAM flags indicating the context of the PAM operation
    ///
    /// # Returns
    /// PAM_SUCESS OR PAM_SYS_ERR
    fn acct_mgmt(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        pam_try!(init_authramp(
            pamh,
            args,
            flags,
            "account",
            |_pamh, _settings, _tally| { Ok(PamResultCode::PAM_SUCCESS) }
        ))
    }
}
