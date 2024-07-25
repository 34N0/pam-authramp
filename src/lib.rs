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
use common::actions::Actions;
use common::settings::Settings;
use pam::conv::Conv;
use pam::pam_try;
use pam::{PamFlag, PamResultCode, PAM_TEXT_INFO};
use pam::{PamHandle, PamHooks};
use std::cmp::min;
use std::ffi::CStr;
use std::thread::sleep;
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
    /// - `pam_h`: `PamHandle` instance for interacting with PAM
    /// - `args`: PAM arguments provided during authentication
    /// - `flags`: PAM flags indicating the context of the PAM operation
    ///
    /// # Returns
    /// `PAM_SUCCESS` OR `PAM_AUTH_ERR`
    fn sm_authenticate(pam_h: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        init_authramp(pam_h, &args, flags, "auth", |pam_h, settings, tally| {
            // match action parameter
            match settings.get_action()? {
                Actions::PREAUTH => Ok(bounce_auth(pam_h, settings, tally)),
                Actions::AUTHFAIL => Err(bounce_auth(pam_h, settings, tally)),
                Actions::AUTHSUCC => Ok(PamResultCode::PAM_SUCCESS),
            }
        })
        .unwrap_or_else(|e| e)
    }

    /// Handles the `acct_mgmt` PAM hook, which is invoked during the account management process.
    ///
    /// This function initializes the `AuthRamp` module by setting up user information and loading settings.
    ///
    /// This hook is only called on sucessful authentication and clears the tally to unlock the account:
    /// account     required                                     `libpam_authramp.so`
    ///
    /// # Arguments
    /// - `pam_h`: `PamHandle` instance for interacting with PAM
    /// - `args`: PAM arguments provided during account management
    /// - `flags`: PAM flags indicating the context of the PAM operation
    ///
    /// # Returns
    /// `PAM_SUCESS` OR `PAM_SYS_ERR`
    fn acct_mgmt(pam_h: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        pam_try!(init_authramp(
            pam_h,
            &args,
            flags,
            "account",
            |_pam_h, _settings, _tally| { Ok(PamResultCode::PAM_SUCCESS) }
        ))
    }

    fn sm_setcred(_pam_h: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}

/// Initializes the authramp module by setting up user information and loading settings.
/// Calls the provided `pam_hook` function with the initialized variables.
///
/// # Arguments
/// - `pam_h`: `PamHandle` instance for interacting with PAM
/// - `_args`: PAM arguments provided during authentication
/// - `_flags`: PAM flags indicating the context of the PAM operation
/// - `pam_hook`: Function to be called with the initialized variables
///
/// # Returns
/// Result from the `pam_hook` function or PAM error code if initialization fails
fn init_authramp<F, R>(
    pam_h: &mut PamHandle,
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
        &pam_h.get_user(None),
        Err(PamResultCode::PAM_AUTH_ERR)
    ));

    // Read configuration file
    let settings = Settings::build(user.clone(), args, flags, pam_hook_desc, Some(pam_h))?;

    // common::util::syslog::init_pam_log(pam_h, &settings)?;

    // Get and Set tally
    let tally = Tally::new_from_tally_file(&Some(pam_h), &settings)?;

    pam_hook(pam_h, &settings, &tally)
}

/// Formats a Duration into a human-readable string representation.
/// The format includes hours, minutes, and seconds, excluding zero values.
///
/// # Arguments
/// - `remaining_time`: Duration representing the remaining time
///
/// # Returns
/// Formatted string indicating the remaining time in the countdown
fn format_remaining_countdown_time(remaining_time: Duration) -> String {
    if remaining_time.num_seconds() == 0 {
        return "..".to_string();
    }

    let mut formatted_time = String::new();

    let mut t_val = remaining_time.num_hours();
    let mut t_desc = "hours";

    if t_val > 0 {
        if t_val == 1 {
            t_desc = t_desc.trim_end_matches('s');
        }
        formatted_time += &format!("{t_val} {t_desc}, ");
    }

    t_val = remaining_time.num_minutes() % 60;
    t_desc = "minutes";

    if t_val > 0 {
        if t_val == 1 {
            t_desc = t_desc.trim_end_matches('s');
        }
        formatted_time += &format!("{t_val} {t_desc} and ");
    }

    t_val = remaining_time.num_seconds() % 60;
    t_desc = "seconds";

    if t_val == 1 {
        t_desc = t_desc.trim_end_matches('s');
    }

    formatted_time += &format!("{t_val} {t_desc}");

    formatted_time
}

fn pam_message(pam_h: &mut PamHandle, msg: &str) -> Result<(), PamResultCode> {
    if let Ok(Some(conv)) = pam_h.get_item::<Conv>() {
        // Send a message to the conversation function
        let conv_res = conv.send(PAM_TEXT_INFO, msg);

        // Log error
        match conv_res {
            Ok(_) => Ok(()),
            Err(pam_code) => {
                match pam_h.log(
                    pam::LogLevel::Error,
                    format!("{pam_code:?}: Error starting PAM conversation."),
                ) {
                    Ok(()) => Ok(()),
                    Err(result_code) => Err(result_code),
                }
            }
        }
    } else {
        match pam_h.log(
            pam::LogLevel::Error,
            "Error accessing conversation in PAM library.".to_string(),
        ) {
            Ok(()) => Ok(()),
            Err(result_code) => Err(result_code),
        }
    }
}

/// Handles the account lockout mechanism based on the number of failures and settings.
/// If the account is locked, it sends periodic messages to the user until the account is unlocked.
///
/// # Arguments
/// - `pam_h`: `PamHandle` instance for interacting with PAM
/// - `settings`: Settings for the authramp module
/// - `tally`: Tally information containing failure count and timestamps
///
/// # Returns
/// `PAM_SUCCESS` if the account is successfully unlocked, `PAM_AUTH_ERR` otherwise
fn bounce_auth(pam_h: &mut PamHandle, settings: &Settings, tally: &Tally) -> PamResultCode {
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
        let delay = tally.get_delay(settings);

        // Calculate the time when the account will be unlocked
        let unlock_instant = tally
            .unlock_instant
            .unwrap_or(tally.failure_instant + delay);

        match pam_h.log(
                pam::LogLevel::Info,
                format!(
                    "PAM_AUTH_ERR: Account {user:?} is getting bounced. Account still locked until {unlock_instant}"
                ),
            ) {
                Ok(()) => (),
                Err(result_code) => return result_code,
            }

        // Don't loop and return timestamp if configured
        if !settings.config.countdown {
            if let Err(result_code) = pam_message(
                pam_h,
                &format!(
                    "Account locked until {}.",
                    unlock_instant.format("%Y-%m-%d %I:%M:%S %p")
                ),
            ) {
                return result_code;
            }
            return PamResultCode::PAM_AUTH_ERR;
        }

        while Utc::now() < unlock_instant {
            // Calculate remaining time until unlock
            let remaining_time = unlock_instant - Utc::now();

            // Cap remaining time at 24 hours
            let capped_remaining_time = min(remaining_time, Duration::hours(24));

            // Only send a message every two seconds to help with latency
            if capped_remaining_time.num_seconds() % 2 == 0 {
                if let Err(result_code) = pam_message(
                    pam_h,
                    &format!(
                        "Account locked! Unlocking in {}.",
                        format_remaining_countdown_time(capped_remaining_time)
                    ),
                ) {
                    return result_code;
                }
            }

            // Wait for one second
            sleep(std::time::Duration::from_secs(1));
        }
    }
    PamResultCode::PAM_SUCCESS
}

// Unit tests
#[cfg(test)]
mod tests {
    use chrono::TimeDelta;

    use super::*;
    use std::time::Duration;

    #[test]
    fn test_format_remaining_time() {
        let cast_error = &"bad time delta!";

        // Test with duration of 2 hours, 24 minutes, and 5 seconds
        let duration =
            TimeDelta::from_std(Duration::new(2 * 3600 + 24 * 60 + 5, 0)).expect(cast_error);
        assert_eq!(
            format_remaining_countdown_time(duration),
            "2 hours, 24 minutes and 5 seconds"
        );

        // Test with duration of 1 hour, 1 minute, and 0 seconds
        let duration = TimeDelta::from_std(Duration::new(3600 + 60, 0)).expect(cast_error);
        assert_eq!(
            format_remaining_countdown_time(duration),
            "1 hour, 1 minute and 0 seconds"
        );

        // Test with duration of 35 seconds
        let duration = TimeDelta::from_std(Duration::new(35, 0)).expect(cast_error);
        assert_eq!(format_remaining_countdown_time(duration), "35 seconds");

        // Test with duration of 35 seconds
        let duration = TimeDelta::from_std(Duration::new(1, 0)).expect(cast_error);
        assert_eq!(format_remaining_countdown_time(duration), "1 second");

        // Test with duration of 0 seconds
        let duration = TimeDelta::from_std(Duration::new(0, 0)).expect(cast_error);
        assert_eq!(format_remaining_countdown_time(duration), "..");
    }
}
