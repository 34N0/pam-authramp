//! # PAM macros module
//!
//! This module provides useful macros for working with PAM.
//!
//! The `pam_hooks!` macro is used to define the hooks that the PAM module provides for
//! various PAM operations, such as account management (`pam_sm_acct_mgmt`) and
//! authentication (`pam_sm_authenticate`). The macro takes the name of a struct that
//! implements the `PamHooks` trait, and generates the necessary extern "C" functions
//! that the PAM library will call.
//!
//! The `pam_try!` macro is a utility macro that simplifies error handling in PAM modules.
//! It takes a `Result` value, and if the result is `Err`, it immediately returns the error
//! code. This allows for more concise error handling code.
//!
//! ## License
//!
//! Copyright 2023 34n0
//!
//! Use of this source code is governed by an MIT-style
//! license that can be found in the LICENSE file or at
//! https://opensource.org/licenses/MIT.

#[macro_export]
macro_rules! pam_hooks {
    ($ident:ident) => {
        pub use self::pam_hooks_scope::*;
        mod pam_hooks_scope {
            use std::ffi::CStr;
            use std::os::raw::{c_char, c_int};
            use $crate::{PamFlag, PamResultCode};
            use $crate::{PamHandle, PamHooks};

            fn extract_argv<'a>(argc: c_int, argv: *const *const c_char) -> Vec<&'a CStr> {
                (0..argc)
                    .map(|o| unsafe { CStr::from_ptr(*argv.offset(o as isize) as *const c_char) })
                    .collect()
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_acct_mgmt(
                pamh: &mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                super::$ident::acct_mgmt(pamh, args, flags)
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_authenticate(
                pamh: &mut PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                super::$ident::sm_authenticate(pamh, args, flags)
            }
        }
    };
}

#[macro_export]
macro_rules! pam_try {
    ($r:expr) => {
        match $r {
            Ok(t) => t,
            Err(e) => return e,
        }
    };
    ($r:expr, $e:expr) => {
        match $r {
            Ok(t) => t,
            Err(_) => return $e,
        }
    };
}
