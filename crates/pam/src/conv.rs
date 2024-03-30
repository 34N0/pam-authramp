//! # PAM conversation module
//!
//! This module provides functions for handling PAM conversation.
//!
//! The PAM conversation function is a callback provided by the application, which is used
//! by the PAM library to communicate with the user. This can include prompting for a password,
//! displaying error messages, or any other interaction with the user.
//!
//! The conversation function is provided to the PAM library by the application in the `pam_conv`
//! structure, which is passed to `pam_start`.
//!
//! The `conv` module provides a safe wrapper around the raw `pam_conv` structure, and includes
//! functions for creating a new `pam_conv` structure, and for invoking the conversation function
//! with a given message style and message string.
//!
//! It also provides the `PamMessageStyle` enum, which represents the different types of messages
//! that can be passed to the conversation function, and the `PamConv` struct, which represents
//! a PAM conversation.
//!
//! ## License
//!
//! Copyright 2023 34n0
//!
//! Use of this source code is governed by an MIT-style
//! license that can be found in the LICENSE file or at
//! https://opensource.org/licenses/MIT.

use libc::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::ptr;

use crate::{items::Item, items::ItemType, PamMessageStyle, PamResult, PamResultCode};

pub type PamItemType = c_int;

#[repr(C)]
struct PamMessage {
    msg_style: PamMessageStyle,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *const c_char,
    resp_retcode: libc::c_int, // Unused - always zero
}

/// `PamConv` acts as a channel for communicating with user.
///
/// Communication is mediated by the pam client (the application that invoked
/// pam).  Messages sent will be relayed to the user by the client, and response
/// will be relayed back.
#[repr(C)]
pub struct Inner {
    conv: extern "C" fn(
        num_msg: c_int,
        pam_message: &&PamMessage,
        pam_response: &mut *const PamResponse,
        appdata_ptr: *const libc::c_void,
    ) -> PamResultCode,
    appdata_ptr: *const libc::c_void,
}

pub struct Conv<'a>(&'a Inner);

impl<'a> Conv<'a> {
    /// Sends a PAM message to the PAM conversation function.
    ///
    /// This allows the PAM module to communicate with the client
    /// application by sending messages, prompts, errors, etc. that
    /// will be displayed to the user.
    /// Sends a message to the pam client.
    ///
    /// This will typically result in the user seeing a message or a prompt.
    /// There are several message styles available:
    ///
    /// - PAM_PROMPT_ECHO_OFF
    /// - PAM_PROMPT_ECHO_ON
    /// - PAM_ERROR_MSG
    /// - PAM_TEXT_INFO
    /// - PAM_RADIO_TYPE
    /// - PAM_BINARY_PROMPT
    ///
    /// Note that the user experience will depend on how the client implements
    /// these message styles - and not all applications implement all message
    /// styles.
    pub fn send(&self, style: PamMessageStyle, msg: &str) -> PamResult<Option<&CStr>> {
        let mut resp_ptr: *const PamResponse = ptr::null();
        let msg_cstr = CString::new(msg).unwrap();
        let msg = PamMessage {
            msg_style: style,
            msg: msg_cstr.as_ptr(),
        };

        let ret = (self.0.conv)(1, &&msg, &mut resp_ptr, self.0.appdata_ptr);

        if PamResultCode::PAM_SUCCESS == ret {
            // PamResponse.resp is null for styles that don't return user input like PAM_TEXT_INFO
            let response = unsafe { (*resp_ptr).resp };
            if response.is_null() {
                Ok(None)
            } else {
                Ok(Some(unsafe { CStr::from_ptr(response) }))
            }
        } else {
            Err(ret)
        }
    }
}

/// Provides implementations for the `Item` trait for `Conv`.
/// This allows a `Conv` to be used as an item in the PAM conversation
/// model.
impl<'a> Item for Conv<'a> {
    type Raw = Inner;

    fn type_id() -> ItemType {
        ItemType::Conv
    }

    unsafe fn from_raw(raw: *const Self::Raw) -> Self {
        Self(&*raw)
    }

    fn into_raw(self) -> *const Self::Raw {
        self.0 as _
    }
}
