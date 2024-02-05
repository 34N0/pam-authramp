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
