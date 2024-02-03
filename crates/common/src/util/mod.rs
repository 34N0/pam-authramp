//! # `AuthRamp` Util Crate
//!
//! General utilities.
//!
//! ## `syslog`
//!
//! The `syslog` module provides functionality for initializing syslog logging in both the PAM module
//! and the CLI binary. It ensures that log messages are sent to the appropriate syslog facility,
//! making it easy to monitor `AuthRamp` activity.
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

pub mod syslog;
