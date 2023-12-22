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
//! ## Commands
//!
//! The available commands include:
//!
//! - **Test:** Build the project, copy the library to the PAM directory, run tests, and clean up.
//! - **PamTest:** Similar to the Test command but focuses on PAM authentication integration tests.
//! - **Lint:** Check code formatting using `cargo fmt` and run clippy for linting.
//! - **Fix:** Automatically fix linting issues using `cargo clippy --fix --allow-dirty`.
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
use clap::{Parser, Subcommand};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use xshell::{cmd, Shell};

const RUNNER: &str = " 
[target.x86_64-unknown-linux-gnu] \n\
runner = 'sudo -E'";

const ALIAS: &str = "[alias] \n\
xtask = 'run --package xtask --'";

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

/// pam-authramp development tool
#[derive(Parser, Debug)]
#[command(arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    // all tests
    Test,
    // pam authentication integration test
    PamTest,
    Lint,
    Fix,
}

/// Main entry point for xtask, parsing command-line arguments and executing corresponding tasks.
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let sh = Shell::new()?;

    match &cli.command {
        Some(Commands::Test) => {
            cmd!(sh, "cargo build").run()?;
            cmd!(
                sh,
                "sudo cp target/debug/libpam_authramp.so /lib64/security"
            )
            .run()?;
            set_and_remove_sudo_runner(|| {
                let _ = cmd!(sh, "cargo test -- --test-threads=1 --show-output").run();
                let _ = cmd!(sh, "sudo rm -f /lib64/security/libpam_authramp.so").run();
                let _ = cmd!(sh, "sudo rm -rf /var/run/authramp").run();
            })
        }
        Some(Commands::Lint) => {
            cmd!(sh, "cargo fmt --check").run()?;
            cmd!(sh, "cargo clippy").run()?;
        }
        Some(Commands::Fix) => {
            cmd!(sh, "cargo fmt").run()?;
            cmd!(sh, "cargo clippy --fix --allow-dirty").run()?;
        }
        Some(Commands::PamTest) => {
            cmd!(sh, "cargo build").run()?;
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
            })
        }
        None => {}
    }
    Ok(())
}
