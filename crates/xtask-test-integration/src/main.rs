//! # XTask Module
//!
//! The `xtask` module provides a set of development tasks and commands for managing
//! the `pam-authramp` project during development. It utilizes the `xshell` crate for
//! shell command execution and automation.
//!
//! ## Cargo Configurations
//!
//! This module sets specific configurations in the `.cargo/config.toml` file during
//! certain tasks. It adds a custom runner for the x86_64-unknown-linux-gnu target and
//! an alias for the xtask package.
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

use anyhow::Ok;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use xshell::{cmd, Shell};

const RUNNER: &str = " 
[target.x86_64-unknown-linux-gnu] \n\
runner = 'sudo -E'";

const ALIAS: &str = "[alias] \n\
test-integration = 'run --package xtask-test-integration --'";

/// Sets specific Cargo configurations and executes a closure that performs additional tasks.
///
/// # Arguments
///
/// - `sudo_f`: A closure containing additional tasks that require elevated privileges.
///
/// # Errors
///
/// Returns an `Result` indicating success or failure.
fn set_and_remove_sudo_runner<F>(sudo_f: F)
where
    F: FnOnce(),
{
    // Open the file in append mode, creating it if it doesn't exist
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(".cargo/config.toml")
        .expect("Unable to open or create file");

    // Append the content to the file
    file.write_all(RUNNER.as_bytes())
        .expect("Unable to write to file");

    sudo_f();

    file = File::create(".cargo/config.toml").expect("Unable to create file");

    file.write_all(ALIAS.as_bytes())
        .expect("Unable to write to file");
}

/// Main entry point for xtask, parsing command-line arguments and executing corresponding tasks.
fn main() -> anyhow::Result<()> {
    let sh = Shell::new()?;

    cmd!(sh, "cargo build -p lib").run()?;
    cmd!(
        sh,
        "sudo cp target/debug/libpam_authramp.so /lib64/security"
    )
    .run()?;
    set_and_remove_sudo_runner(|| {
        let _ = cmd!(
            sh,
            "cargo test --test '*' -- --test-threads=1 --show-output"
        )
        .run();
        let _ = cmd!(sh, "sudo rm -f /lib64/security/libpam_authramp.so").run();
        let _ = cmd!(sh, "sudo rm -rf /var/run/authramp").run();
    });
    Ok(())
}
