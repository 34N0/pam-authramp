//! # Test Utilities Module
//!
//! The `test_utils` module provides utility functions for testing the rampdelay PAM module. It
//! includes functions to create and remove PAM service files, clear the tally directory, and
//! initialize and clear the testing environment. Additionally, it offers functions to obtain a
//! PAM context and the path to a user's tally file.
//!
//! ## PAM Service File
//!
//! The PAM service file is a configuration file used to define PAM services. The module includes
//! functions to create and remove a PAM service file specific to the rampdelay module during tests.
//!
//! ## Tally Directory
//!
//! The tally directory is a location where user-specific tally files are stored. The module
//! provides a function to clear this directory to ensure a clean testing environment.
//!
//! ## Initialization and Cleanup
//!
//! The `init_and_clear_test` function is a convenient utility for initializing and cleaning up the
//! testing environment. It creates the PAM service file, executes the provided test function, and
//! then removes the PAM service file and clears the tally directory.
//!
//! ## PAM Context
//!
//! The `get_pam_context` function creates a PAM context for testing purposes. It takes a username
//! and password, initializes a PAM context with the rampdelay PAM service, and sets up a
//! conversation with the provided credentials.
//!
//! ## Tally File Path
//!
//! The `get_tally_file_path` function constructs the path to a user's tally file within the tally
//! directory.
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

use std::fs::remove_dir_all;
use std::io;
use std::path::PathBuf;

use std::{
    fs::{remove_file, File},
    io::Write,
};

use pam_client::conv_mock::Conversation;
use pam_client::Context;

pub const SRV_DIR: &str = "/etc/pam.d";
pub const PAM_SRV: &str = "test-rampdelay";

fn create_pam_service_file() -> io::Result<()> {
    let mut file = File::create(PathBuf::from(SRV_DIR).join(PAM_SRV))?;

    let content = "auth        required                                     libpam_authramp.so preauth \n\
                  auth        sufficient                                   pam_unix.so nullok \n\
                  auth        [default=die]                                libpam_authramp.so authfail \n\
                  account     required                                     libpam_authramp.so";

    file.write_all(content.as_bytes())?;
    Ok(())
}

fn remove_pam_service_file() -> io::Result<()> {
    remove_file(PathBuf::from(SRV_DIR).join(PAM_SRV))?;
    Ok(())
}

fn clear_tally_dir() -> Result<(), io::Error> {
    remove_dir_all("/var/run/rampdelay")?;
    Ok(())
}

pub fn init_and_clear_test<F>(test: F)
where
    F: FnOnce(),
{
    create_pam_service_file().expect("Failed to create PAM service file");
    test();
    remove_pam_service_file().expect("Failed to remove PAM service file");
    clear_tally_dir().expect("Failes clearing tally dir");
}

pub fn get_pam_context(u_name: &str, u_pwd: &str) -> Context<Conversation> {
    Context::new(PAM_SRV, None, Conversation::with_credentials(u_name, u_pwd))
        .expect("Failed creating PAM context!")
}

pub fn get_tally_file_path(u_name: &str) -> PathBuf {
    PathBuf::from("/var/run/rampdelay").join(u_name)
}
