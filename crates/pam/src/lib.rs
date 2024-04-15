//! # PAM Module
//!
//! This is the main module of the PAM library. It provides the main data structures and functions
//! for interacting with the Pluggable Authentication Modules (PAM) system.
//!
//! The main types provided by this module are:
//! - `PamHandle`: An opaque type that represents a handle to the PAM context. This handle is
//!   used to make API calls to the PAM system.
//! - `PamResultCode`: An enum representing the possible result codes that can be returned by
//!   PAM functions.
//! - `PamFlag`: An enum representing the possible flags that can be passed to PAM functions.
//! - `LogLevel`: An enum representing the possible log levels that can be used when logging
//!   messages with the `pam_syslog` function.
//!
//! This module also provides the `PamHooks` trait, which can be implemented by types that
//! provide hooks for various PAM operations, such as account management and authentication.
//!
//!  ## License
//!
//! Copyright 2023 34n0
//!
//! Use of this source code is governed by an MIT-style
//! license that can be found in the LICENSE file or at
//! https://opensource.org/licenses/MIT.

pub mod conv;
pub mod items;
pub mod macros;

use libc::c_char;
use std::ffi::{CStr, CString};

use libc::{c_int, c_uint};

pub type PamFlag = c_uint;
pub type PamMessageStyle = c_int;

pub const PAM_ERROR_MSG: PamMessageStyle = 3;
pub const PAM_TEXT_INFO: PamMessageStyle = 4;

#[allow(non_camel_case_types, dead_code)]
#[derive(Debug, PartialEq)]
#[repr(C)]
pub enum PamResultCode {
    PAM_SUCCESS = 0,
    PAM_SYSTEM_ERR = 4,
    PAM_PERM_DENIED = 6,
    PAM_AUTH_ERR = 7,
    PAM_USER_UNKNOWN = 10,
    PAM_CONV_ERR = 19,
    PAM_IGNORE = 25,
    PAM_ABORT = 26,
}

pub enum LogLevel {
    /// system is unusable, corresponds to LOG_EMERG
    Emergency = 0,
    /// action must be taken immediately, corresponds to LOG_ALERT
    Alert = 1,
    /// critical conditions, corresponds to LOG_CRIT
    Critical = 2,
    /// error conditions, corresponds to LOG_ERR
    Error = 3,
    /// warning conditions, corresponds to LOG_WARN
    Warning = 4,
    /// normal, but significant, condition, corresponds to LOG_NOTICE
    Notice = 5,
    /// informational message, corresponds to LOG_INFO
    Info = 6,
    /// debug-level message, corresponds to LOG_DEBUG
    Debug = 7,
}

/// Opaque type, used as a pointer when making pam API calls.
///
/// A module is invoked via an external function such as `pam_sm_authenticate`.
/// Such a call provides a pam handle pointer.  The same pointer should be given
/// as an argument when making API calls.
#[repr(C)]
pub struct PamHandle {
    _data: [u8; 0],
}

#[link(name = "pam")]
extern "C" {
    fn pam_get_user(
        pamh: *const PamHandle,
        user: &*mut c_char,
        prompt: *const c_char,
    ) -> PamResultCode;

    fn pam_get_item(
        pamh: *const PamHandle,
        item_type: items::ItemType,
        item: &mut *const libc::c_void,
    ) -> PamResultCode;

    fn pam_syslog(
        pamh: *const PamHandle,
        priority: libc::c_int,
        format: *const c_char,
        ...
    ) -> PamResultCode;
}

pub type PamResult<T> = Result<T, PamResultCode>;

impl PamHandle {
    /// Retrieves the name of the user who is authenticating or logging in.
    ///
    /// This is really a specialization of `get_item`.
    ///
    /// See `pam_get_user` in
    /// http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PAM function call fails.
    ///
    /// # Panics
    ///
    /// Panics if the provided prompt string contains a nul byte
    pub fn get_user(&self, prompt: Option<&str>) -> PamResult<String> {
        let ptr: *mut c_char = std::ptr::null_mut();
        let prompt_string;
        let c_prompt = match prompt {
            Some(p) => {
                prompt_string = CString::new(p).unwrap();
                prompt_string.as_ptr()
            }
            None => std::ptr::null(),
        };
        let res = unsafe { pam_get_user(self, &ptr, c_prompt) };
        if PamResultCode::PAM_SUCCESS == res && !ptr.is_null() {
            let const_ptr = ptr as *const c_char;
            let bytes = unsafe { CStr::from_ptr(const_ptr).to_bytes() };
            String::from_utf8(bytes.to_vec()).map_err(|_| PamResultCode::PAM_CONV_ERR)
        } else {
            Err(res)
        }
    }

    /// Retrieves a value that has been set, possibly by the pam client.  This is
    /// particularly useful for getting a `PamConv` reference.
    ///
    /// See `pam_get_item` in
    /// http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PAM function call fails.
    pub fn get_item<T: items::Item>(&self) -> PamResult<Option<T>> {
        let mut ptr: *const libc::c_void = std::ptr::null();
        let (res, item) = unsafe {
            let r = pam_get_item(self, T::type_id(), &mut ptr);
            let typed_ptr = ptr.cast::<T::Raw>();
            let t = if typed_ptr.is_null() {
                None
            } else {
                Some(T::from_raw(typed_ptr))
            };
            (r, t)
        };
        if PamResultCode::PAM_SUCCESS == res {
            Ok(item)
        } else {
            Err(res)
        }
    }

    /// Log a message with the specified level to the syslog.
    ///
    /// This method wraps pam_syslog, which prefixes the message with a string indicating
    /// the relevant PAM context.
    pub fn log(&self, level: LogLevel, message: String) -> Result<(), PamResultCode> {
        let percent_s = CString::new("%s").map_err(|_| PamResultCode::PAM_SYSTEM_ERR)?;
        let message = CString::new(message).map_err(|_| PamResultCode::PAM_SYSTEM_ERR)?;
        let res = unsafe { pam_syslog(self, level as i32, percent_s.as_ptr(), message.as_ptr()) };
        if PamResultCode::PAM_SUCCESS == res {
            Ok(())
        } else {
            Err(res)
        }
    }
}

/// Provides functions that are invoked by the entrypoints generated by the
/// [`pam_hooks!` macro](../macro.pam_hooks.html).
///
/// All of hooks are ignored by PAM dispatch by default given the default return value of `PAM_IGNORE`.
/// Override any functions that you want to handle with your module. See `man pam(3)`.
#[allow(unused_variables)]
pub trait PamHooks {
    /// This function performs the task of establishing whether the user is permitted to gain access at
    /// this time. It should be understood that the user has previously been validated by an
    /// authentication module. This function checks for other things. Such things might be: the time of
    /// day or the date, the terminal line, remote hostname, etc. This function may also determine
    /// things like the expiration on passwords, and respond that the user change it before continuing.
    fn acct_mgmt(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// Is not actually implemented, but still needs to be exposed to fix some instabilitry issues.
    fn sm_setcred(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }
}
