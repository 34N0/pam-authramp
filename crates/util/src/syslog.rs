//! # Syslog Module
//!
//! The `my_syslog` module manages syslog logging for the authramp PAM module. It initializes the
//! syslog logger and provides macros for logging informational and error messages with additional
//! context.
//!
//! ## Overview
//!
//! The module defines a structure `SyslogState` to hold the syslog logger state, including
//! initialization status and a pre-formatted log string. It also exposes a static variable
//! `SYSLOG_STATE` to store the syslog state. The `init_log` function initializes the syslog logger,
//! and the `syslog_info` and `syslog_error` macros are used for logging messages at different levels.
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

use log::LevelFilter;
use pam::module::PamHandle;
use pam::{constants::PamResultCode, items::Service};
use sysinfo::{Pid, System};
use syslog::{BasicLogger, Facility, Formatter3164};

use crate::settings::Settings;

/// Constants
const MODULE_NAME: &str = "pam_authramp";

/// Struct to hold syslog state
pub struct LogState {
    pub logger_initialized: bool,
    pub pre_log: Option<String>,
}

/// Static variable to hold syslog state
pub static mut SYSLOG_STATE: LogState = LogState {
    logger_initialized: false,
    pre_log: None,
};

/// Initializes syslog logging for PAM services.
///
/// This function should be called once from outside the module to set up the syslog logger.
/// It initializes the logger with syslog settings, such as the facility, process name, etc.
/// The resulting logger is used by the `syslog_info` and `syslog_error` macros.
///
/// # Arguments
///
/// * `pamh` - A mutable reference to the PAM handle.
/// * `settings` - A reference to the Settings struct containing configuration information.
///
/// # Returns
///
/// Returns Ok(()) on success, or Err(PamResultCode) on failure.
///
/// # Errors
///
/// Returns a `PamResultCode` error.
pub fn init_pam_log(pamh: &mut PamHandle, settings: &Settings) -> Result<(), PamResultCode> {
    unsafe {
        if !SYSLOG_STATE.logger_initialized {
            let service_name = pamh.get_item::<Service>().ok().flatten().map_or_else(
                || "unknown-service".to_string(),
                |service| service.to_str().unwrap_or("unknown-service").to_string(),
            );

            let mut sys = System::new_all();
            sys.refresh_all();

            let process_name = sys
                .process(Pid::from_u32(std::process::id()))
                .map_or("unknown-process".to_string(), |p| p.name().to_string());

            let formatter = Formatter3164 {
                facility: Facility::LOG_USER,
                hostname: None,
                process: process_name,
                pid: 0,
            };

            let logger = match syslog::unix(formatter) {
                Err(_) => return Err(PamResultCode::PAM_SYSTEM_ERR),
                Ok(logger) => logger,
            };

            log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
                .map(|()| log::set_max_level(LevelFilter::Info))
                .map_err(|_| PamResultCode::PAM_SYSTEM_ERR)?;

            SYSLOG_STATE.logger_initialized = true;

            let pre_log = format!("{}({}:{})", MODULE_NAME, service_name, settings.pam_hook);
            SYSLOG_STATE.pre_log = Some(pre_log);
        }
        Ok(())
    }
}

/// Initializes syslog logging for the cli.
///
/// This function should be called once from outside the module to set up the syslog logger.
/// It initializes the logger with syslog settings, such as the facility, process name, etc.
/// The resulting logger is used by the `syslog_info` and `syslog_error` macros.
///
///
/// # Returns
///
/// Returns Ok(()) on success, or Err(PamResultCode) on failure.
///
/// # Errors
///
/// Returns a `PamResultCode` error.
pub fn init_cli_log() -> Result<(), PamResultCode> {
    unsafe {
        if !SYSLOG_STATE.logger_initialized {
            let mut sys = System::new_all();
            sys.refresh_all();

            let process_name = sys
                .process(Pid::from_u32(std::process::id()))
                .map_or("unknown-process".to_string(), |p| p.name().to_string());

            let formatter = Formatter3164 {
                facility: Facility::LOG_USER,
                hostname: None,
                process: process_name,
                pid: 0,
            };

            let logger = match syslog::unix(formatter) {
                Err(_) => return Err(PamResultCode::PAM_SYSTEM_ERR),
                Ok(logger) => logger,
            };

            log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
                .map(|()| log::set_max_level(LevelFilter::Info))
                .map_err(|_| PamResultCode::PAM_SYSTEM_ERR)?;

            SYSLOG_STATE.logger_initialized = true;

            let pre_log = format!("{}({})", MODULE_NAME, "CLI");
            SYSLOG_STATE.pre_log = Some(pre_log);
        }
        Ok(())
    }
}

/// Macro for logging informational messages.
///
/// This macro logs messages at the "info" level using the syslog logger.
///
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        {
            unsafe {
                if $crate::syslog::SYSLOG_STATE.logger_initialized {
                    if let Some(ref pre_log) = $crate::syslog::SYSLOG_STATE.pre_log {
                        log::info!("{}: {}", pre_log, format_args!($($arg)*));
                    }
                }
            }
        }
    };
}

/// Macro for logging error messages.
///
/// This macro logs messages at the "error" level using the syslog logger.
///
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        {
            unsafe {
                if $crate::syslog::SYSLOG_STATE.logger_initialized {
                    if let Some(ref pre_log) = $crate::syslog::SYSLOG_STATE.pre_log {
                        log::error!("{}: {}", pre_log, format_args!($($arg)*));
                    }
                }
            }
        }
    };
}
