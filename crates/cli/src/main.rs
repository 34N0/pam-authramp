//! # `AuthRamp` CLI Binary
//!
//! The `authramp` CLI binary provides a command-line interface for interacting with the `AuthRamp` PAM module.
//! It includes subcommands to perform various actions, such as resetting a locked PAM user.
//!
//! # Usage
//!
//! To use the `authramp` CLI binary, run it from the command line with the desired subcommand and options.
//!
//! # Example
//!
//! ```bash
//! # Reset a locked PAM user
//! authramp reset --user example_user
//! ```
//!
//! # Commands
//!
//! - [`reset`](cmd/reset/index.html): Resets a locked PAM user.
//!
//! # Structs
//!
//! - [`ArCliError`](struct.ArCliError.html): Represents an error result in the `AuthRamp` CLI.
//! - [`ArCliSuccess`](struct.ArCliSuccess.html): Represents a success result in the `AuthRamp` CLI.
//! - [`ArCliInfo`](struct.ArCliInfo.html): Represents an informational result in the `AuthRamp` CLI.
//! - [`ArCliResult`](struct.ArCliResult.html): Represents the result of a command execution in the `AuthRamp` CLI.
//! - [`Cli`](struct.Cli.html): Represents the main CLI struct.
//! - [`Command`](enum.Command.html): Represents the available subcommands.
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

use clap::{Parser, Subcommand};
use cmd::reset;
use colored::Colorize;
use std::fmt;
use common::{log_error, log_info, util::syslog};
mod cmd;

const BANNER: &str = r" 

 █████ ██    ████████████   ████████  █████ ███    █████████  
██   ████    ██   ██   ██   ████   ████   ██████  ██████   ██ 
█████████    ██   ██   █████████████ █████████ ████ ████████  
██   ████    ██   ██   ██   ████   ████   ████  ██  ████      
██   ██ ██████    ██   ██   ████   ████   ████      ████

by 34n0@immerda.ch";

#[derive(Debug)]
pub struct ArCliError {
    message: String,
}

impl fmt::Display for ArCliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", "error:".red().bold(), self.message)
    }
}

#[derive(Debug)]
pub struct ArCliSuccess {
    message: String,
}

impl fmt::Display for ArCliSuccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", "success:".green().bold(), self.message)
    }
}

#[derive(Debug)]
pub struct ArCliInfo {
    message: String,
}

impl fmt::Display for ArCliInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", "info:".yellow().bold(), self.message)
    }
}

#[derive(Debug)]
pub enum ArCliResult {
    Success(Option<ArCliSuccess>),
    Info(ArCliInfo),
    Error(ArCliError),
}

impl fmt::Display for ArCliResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArCliResult::Success(Some(ref success)) => write!(f, "{success}"),
            ArCliResult::Success(None) => Ok(()),
            ArCliResult::Error(ref error) => write!(f, "{error}"),
            ArCliResult::Info(ref info) => write!(f, "{info}"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    arg_required_else_help = true,
    author = "34n0",
    about = &BANNER,
)]

struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(about = "Reset a locked PAM user")]
    Reset {
        #[clap(long, short)]
        user: String,
    },
}

/// Main entry point for the `AuthRamp` CLI binary.
///
/// Initializes the syslog, parses command-line arguments, executes the corresponding subcommand,
/// and prints the result.
fn main() {
    syslog::init_cli_log().unwrap_or_else(|e| println!("{e:?}: Error initializing cli log:"));

    let cli_res = match Cli::parse().command {
        Some(Command::Reset { user }) => reset::user(&user),
        _ => ArCliResult::Success(None),
    };

    // Log the result
    match &cli_res {
        ArCliResult::Success(res) => {
            if let Some(res) = res {
                log_info!("{}", &res.message);
            }
        }
        ArCliResult::Error(res) => {
            log_error!("{}", &res.message);
        }
        ArCliResult::Info(_) => (),
    }

    // Print the result
    println!("{cli_res}");
}
