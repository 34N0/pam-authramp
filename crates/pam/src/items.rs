//! # PAM items module
//!
//! This module defines the `Item` trait and its associated `ItemType` enum.
//!
//! The `Item` trait represents a piece of data (an item) that can be stored in a PAM context.
//! Each item is identified by its `ItemType`, and can be retrieved from the PAM context using
//! the `get_item` method, and stored in the PAM context using the `set_item` method.
//!
//! The `ItemType` enum represents the different types of items that can be stored in a PAM context.
//! Each item type corresponds to a specific piece of data, such as the user's username, password,
//! or the PAM conversation function.
//!
//! This module also provides implementations of the `Item` trait for several types, including
//! `CString`, `Conv`, and `Option<CString>`.
//!
//! ## License
//! 
//! Copyright 2023 34n0
//! 
//! Use of this source code is governed by an MIT-style
//! license that can be found in the LICENSE file or at
//! https://opensource.org/licenses/MIT.

#[repr(u32)]
pub enum ItemType {
    /// The pam_conv structure
    Conv = 5,
}

// A type that can be requested by `pam::Handle::get_item`.
pub trait Item {
    /// The `repr(C)` type that is returned (by pointer) by the underlying `pam_get_item` function.
    type Raw;

    /// The `ItemType` for this type
    fn type_id() -> ItemType;

    /// The function to convert from the pointer to the C-representation to this safer wrapper type
    ///
    /// # Safety
    ///
    /// This function can assume the pointer is a valid pointer to a `Self::Raw` instance.
    unsafe fn from_raw(raw: *const Self::Raw) -> Self;

    /// The function to convert from this wrapper type to a C-compatible pointer.
    fn into_raw(self) -> *const Self::Raw;
}
