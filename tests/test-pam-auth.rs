//! # PAM Auth Integration Test module
//!
//! The `test-pam-auth` module contains integration tests for the authramp PAM module. These tests
//! simulate authentication scenarios and validate the behavior of the module, including tally file
//! creation, tally count updates, and successful authentication clearing the tally.
//!
//! ## Issues
//!
//! Because this module uses the systems pam these tests need to be run with evelated privileges.
//! Also the library needs to be built and copied to the correct location.
//! These tests will thus only run correctly via the `cargo xtask test` or `cargo xtask pam-test` commands.
//!
//! ## Test Scenarios
//!
//! The integration tests cover the following scenarios:
//!
//! - **Valid Authentication Success:** Tests a valid authentication attempt, expecting success.
//!
//! - **Invalid Authentication Creates Tally:** Tests an invalid authentication attempt, expecting
//!   the creation of a tally file.
//!
//! - **Consecutive Invalid Adds Tally:** Tests consecutive invalid authentication attempts, expecting
//!   the tally count to increase.
//!
//! - **Valid Authentication Clears Tally:** Tests a valid authentication attempt after consecutive
//!   invalid attempts, expecting the tally count to reset to 0.
//!
//! ## Test Initialization and Cleanup
//!
//! The `init_and_clear_test` function is utilized to initialize the testing environment, perform
//! the tests, and clear the environment afterward.
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

#[macro_use]
extern crate dotenv_codegen;

mod common;

#[cfg(test)]
mod test_pam_auth {

    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    use crate::common::utils::get_pam_context;

    use super::common::utils;
    use pam_client::Flag;

    const USER_NAME: &str = dotenv!("TEST_USER_NAME");
    const USER_PWD: &str = dotenv!("TEST_USER_PWD");

    #[test]
    fn test_valid_auth_success() {
        utils::init_and_clear_test(|| {
            let mut ctx = get_pam_context(USER_NAME, USER_PWD);

            // Expect the authentication to succeed
            ctx.authenticate(Flag::NONE).expect("Authentication failed");
            ctx.acct_mgmt(Flag::NONE)
                .expect("Account management failed")
        });
    }

    #[test]
    fn test_invalid_auth_creates_tally() {
        utils::init_and_clear_test(|| {
            let mut ctx = get_pam_context(USER_NAME, "INVALID");

            // Expect an error during authentication (invalid credentials)
            let auth_result = ctx.authenticate(Flag::NONE);
            assert!(auth_result.is_err(), "Authentication succeeded!");

            // Expect tally file gets created
            let tally_file_path = utils::get_tally_file_path(USER_NAME);
            assert!(tally_file_path.exists(), "Tally file not created")
        });
    }

    #[test]
    fn test_consecutive_invalid_adds_tally() {
        utils::init_and_clear_test(|| {
            let mut ctx = get_pam_context(USER_NAME, "INVALID");

            let mut count = 0;
            let total_tries = 2;

            while count < total_tries {
                // Expect an error during authentication (invalid credentials)
                let auth_result = ctx.authenticate(Flag::NONE);
                assert!(auth_result.is_err(), "Authentication succeeded!");

                count += 1;
            }

            // Expect tally file gets created
            let tally_file_path = utils::get_tally_file_path(USER_NAME);
            assert!(tally_file_path.exists(), "Tally file not created");

            // Expect tally count
            let ini_content = fs::read_to_string(tally_file_path).unwrap();
            assert!(ini_content.contains(&format!("count={}", total_tries)));
        })
    }

    #[test]
    fn test_valid_auth_clears_tally() {
        utils::init_and_clear_test(|| {
            let mut ctx = get_pam_context(USER_NAME, "INVALID");

            // Expect an error during authentication (invalid credentials)
            let auth_result = ctx.authenticate(Flag::NONE);
            assert!(auth_result.is_err(), "Authentication succeeded!");

            // Expect tally file gets created
            let tally_file_path = utils::get_tally_file_path(USER_NAME);
            assert!(tally_file_path.exists(), "Tally file not created");

            // Expect tally count to increase
            let ini_content = fs::read_to_string(&tally_file_path).unwrap();
            assert!(
                ini_content.contains("count=1"),
                "Expected tally count to increase"
            );

            let mut ctx = get_pam_context(USER_NAME, USER_PWD);

            // Expect an error during authentication (invalid credentials)
            let auth_result = ctx.authenticate(Flag::NONE);
            assert!(auth_result.is_ok(), "Authentication failed!");

            ctx.acct_mgmt(Flag::NONE)
                .expect("Account management failed");

            // Expect tally count to decrease
            let ini_content = fs::read_to_string(&tally_file_path).unwrap();
            assert!(ini_content.contains("count=0"), "Expected tally count = 0");
        });
    }

    #[test]
    fn test_exceeding_free_tries_causes_bounce() {
        utils::init_and_clear_test(|| {
            let user_name = "user";
            let user_pwd = "INVALID PASSWORD";

            // Step 0: Attempt authentication
            let mut ctx = get_pam_context(user_name, user_pwd);

            // Expect an error during authentication (invalid credentials)
            let auth_result = ctx.authenticate(Flag::NONE);
            assert!(auth_result.is_err(), "Authentication succeeded!");

            // Expect tally file gets created
            let tally_file_path = utils::get_tally_file_path(USER_NAME);
            assert!(tally_file_path.exists(), "Tally file not created");

            let mut a_count = 0;

            while a_count < 6 {
                // Expect an error during authentication (invalid credentials)
                let auth_result = ctx.authenticate(Flag::NONE);
                assert!(auth_result.is_err(), "Authentication succeeded!");
                a_count += 1;
            }

            // Check if the conversation log contains the expected bounce message
            let bounce_message = "Account locked! Unlocking in 29";
            let log = &ctx.conversation().log;

            let log_str = format!("{:?}", log);

            assert!(
                log_str.contains(bounce_message),
                "Conversation log does not contain expected bounce message"
            );
        });
    }

    #[test]
    fn test_custom_tally_dir() {
        utils::init_and_clear_test(|| {
            // Create a temporary directory for the custom tally_dir
            let custom_tally_dir = TempDir::new().expect("Unable to create temporary directory");

            // Set the custom tally_dir path in authramp.conf
            let config_content = format!(
                "[Settings]\n\
                tally_dir = {}\n\
                free_tries = 6\n\
                base_delay_seconds = 30\n\
                ramp_multiplier = 50\n",
                custom_tally_dir.path().display()
            );
            let config_path = "/etc/security/authramp.conf";
            fs::write(config_path, config_content).expect("Unable to write to authramp.conf");

            // Attempt authentication (which will fail)
            let user_name = dotenv!("TEST_USER_NAME");
            let mut ctx = get_pam_context(user_name, "INVALID");
            let auth_result = ctx.authenticate(Flag::NONE);
            assert!(auth_result.is_err(), "Authentication succeeded!");

            // Check if the tally file is created in the custom tally_dir path
            let tally_file_path = custom_tally_dir.path().join(user_name);
            assert!(
                Path::exists(&tally_file_path),
                "Tally file not created in custom tally_dir"
            );

            fs::remove_file(config_path).expect("Unable to remove test config");
            fs::remove_dir_all(custom_tally_dir.path()).expect("Unable to remove custom tally dir");
        });
    }
}
