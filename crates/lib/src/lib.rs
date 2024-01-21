//! # `AuthRamp` PAM Module
//!
//! The `AuthRamp` PAM (Pluggable Authentication Modules) module provides an account lockout mechanism
//! based on the number of authentication failures. It calculates a dynamic delay for subsequent
//! authentication attempts, increasing the delay with each failure to mitigate brute force attacks.
//!
//! ## Usage
//!
//! To use the `AuthRamp` PAM module, integrate it with the PAM system by configuring the `/etc/pam.d/`
//! configuration files for the desired PAM-aware services. This module is designed for the
//! `sm_authenticate` and `acct_mgmt` hooks.
//!
//! ## Configuration
//!
//! The behavior of the `AuthRamp` module is configurable through an TOML file located at
//! `/etc/security/authramp.conf` by default. The configuration file can be customized with settings
//! such as the tally directory, free tries threshold, base delay, and multiplier.
//!
//! ```ini
//! [Configuration]
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

mod tally;

use chrono::{Duration, Utc};
use pam::constants::{PamFlag, PamResultCode, PAM_ERROR_MSG};
use pam::conv::Conv;
use pam::module::{PamHandle, PamHooks};
use pam::pam_try;
use std::cmp::min;
use std::ffi::CStr;
use std::thread::sleep;
use util::settings::Settings;
use util::types::Actions;
use util::{log_error, log_info};
use uzers::get_user_by_name;

use tally::Tally;

pub struct Pamauthramp;

pam::pam_hooks!(Pamauthramp);
impl PamHooks for Pamauthramp {
    /// Handles the `sm_authenticate` PAM hook, which is invoked during the authentication process.
    ///
    /// This function initializes the `AuthRamp` module by setting up user information and loading settings.
    ///
    /// This can be called with the PREAUTH action argument:
    /// auth        required                                     `libpam_authramp.so` preauth
    /// It then checks if an account is locked. And if that is true it bounces the auth.
    ///
    /// It can also be called with the AUTHFAIL action argument:
    /// auth        [default=die]                                `libpam_authramp.so` authfail
    /// It then locks the account and increments the delay.
    ///
    /// # Arguments
    /// - `pamh`: `PamHandle` instance for interacting with PAM
    /// - `args`: PAM arguments provided during authentication
    /// - `flags`: PAM flags indicating the context of the PAM operation
    ///
    /// # Returns
    /// `PAM_SUCCESS` OR `PAM_AUTH_ERR`
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        init_authramp(pamh, &args, flags, "auth", |pamh, settings, tally| {
            // match action parameter
            match settings.get_action()? {
                Actions::PREAUTH => {
                    // if account is locked then bounce
                    if tally.failures_count > settings.config.free_tries {
                        Err(bounce_auth(pamh, settings, tally))
                    } else {
                        Ok(PamResultCode::PAM_SUCCESS)
                    }
                }
                // bounce if called with authfail
                Actions::AUTHFAIL => Err(bounce_auth(pamh, settings, tally)),
                Actions::AUTHSUCC => Err(PamResultCode::PAM_AUTH_ERR),
            }
        })
        .unwrap_or(PamResultCode::PAM_SUCCESS)
    }

    /// Handles the `acct_mgmt` PAM hook, which is invoked during the account management process.
    ///
    /// This function initializes the `AuthRamp` module by setting up user information and loading settings.
    ///
    /// This hook is only called on sucessful authentication and clears the tally to unlock the account:
    /// account     required                                     `libpam_authramp.so`
    ///
    /// # Arguments
    /// - `pamh`: `PamHandle` instance for interacting with PAM
    /// - `args`: PAM arguments provided during account management
    /// - `flags`: PAM flags indicating the context of the PAM operation
    ///
    /// # Returns
    /// `PAM_SUCESS` OR `PAM_SYS_ERR`
    fn acct_mgmt(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        pam_try!(init_authramp(
            pamh,
            &args,
            flags,
            "account",
            |_pamh, _settings, _tally| { Ok(PamResultCode::PAM_SUCCESS) }
        ))
    }
}

/// Initializes the authramp module by setting up user information and loading settings.
/// Calls the provided `pam_hook` function with the initialized variables.
///
/// # Arguments
/// - `pamh`: `PamHandle` instance for interacting with PAM
/// - `_args`: PAM arguments provided during authentication
/// - `_flags`: PAM flags indicating the context of the PAM operation
/// - `pam_hook`: Function to be called with the initialized variables
///
/// # Returns
/// Result from the `pam_hook` function or PAM error code if initialization fails
fn init_authramp<F, R>(
    pamh: &mut PamHandle,
    args: &[&CStr],
    flags: PamFlag,
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
    let settings = Settings::build(user.clone(), args, flags, pam_hook_desc)?;

    util::syslog::init_pam_log(pamh, &settings)?;

    // Get and Set tally
    let tally = Tally::new_from_tally_file(&settings)?;

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
    fn append_unit(value: i64, unit: &str, formatted_time: &mut String) {
        if value > 0 {
            let unit_str = if value == 1 {
                unit.trim_end_matches('s')
            } else {
                unit
            };
            formatted_time.push_str(&format!("{value} {unit_str} "));
        }
    }

    let mut formatted_time = String::new();

    append_unit(remaining_time.num_hours(), "hour", &mut formatted_time);
    append_unit(
        remaining_time.num_minutes() % 60,
        "minutes",
        &mut formatted_time,
    );
    append_unit(
        remaining_time.num_seconds() % 60,
        "seconds",
        &mut formatted_time,
    );

    formatted_time
}

/// Handles the account lockout mechanism based on the number of failures and settings.
/// If the account is locked, it sends periodic messages to the user until the account is unlocked.
///
/// # Arguments
/// - `pamh`: `PamHandle` instance for interacting with PAM
/// - `settings`: Settings for the authramp module
/// - `tally`: Tally information containing failure count and timestamps
///
/// # Returns
/// `PAM_SUCCESS` if the account is successfully unlocked, `PAM_AUTH_ERR` otherwise
fn bounce_auth(pamh: &mut PamHandle, settings: &Settings, tally: &Tally) -> PamResultCode {
    // get user
    let user = match settings.get_user() {
        Ok(user) => user,
        Err(res) => return res,
    };

    // ignore root except when configured
    if user.uid().eq(&0) && !settings.config.even_deny_root {
        return PamResultCode::PAM_SUCCESS;
    }

    if tally.failures_count > settings.config.free_tries {
        if let Ok(Some(conv)) = pamh.get_item::<Conv>() {
            let delay = tally.get_delay(settings);

            // Calculate the time when the account will be unlocked
            let unlock_instant = tally
                .unlock_instant
                .unwrap_or(tally.failure_instant + delay);

            log_info!(
                "PAM_AUTH_ERR: Account {:?} is getting bounced. Account still locked until {}",
                user,
                unlock_instant,
            );

            while Utc::now() < unlock_instant {
                // Calculate remaining time until unlock
                let remaining_time = unlock_instant - Utc::now();

                // Cap remaining time at 24 hours
                let capped_remaining_time = min(remaining_time, Duration::hours(24));

                // Send a message to the conversation function
                let conv_res = conv.send(
                    PAM_ERROR_MSG,
                    &format!(
                        "Account locked! Unlocking in {}.",
                        format_remaining_time(capped_remaining_time)
                    ),
                );

                // Log Conversation Error but continue loop
                match conv_res {
                    Ok(_) => (),
                    Err(pam_code) => {
                        log_error!("{:?}: Error starting PAM conversation.", pam_code);
                    }
                }

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
