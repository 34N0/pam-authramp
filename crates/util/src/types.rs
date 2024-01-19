//! # Types Module
//!
//! The `types` module defines custom types and enumerations used across the `AuthRamp` library.
//! It includes types such as `Actions` and other utility types.
//!
//! # Usage
//!
//! To use the `types` module, import the necessary types into your code and use them as needed.
//!
//! # Enumerations
//!
//! - [`Actions`](enum.Actions.html): Represents different actions in the `AuthRamp` library.
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

// Action argument defines position in PAM stack
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum Actions {
    PREAUTH,
    AUTHSUCC,
    #[default]
    AUTHFAIL,
}
