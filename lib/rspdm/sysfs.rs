// SPDX-License-Identifier: GPL-2.0
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! https://www.dmtf.org/dsp/DSP0274
//!
//! Rust sysfs helper functions
//!
//! Copyright (C) 2024 Western Digital

use crate::SpdmState;
use kernel::prelude::*;
use kernel::{bindings, fmt, str::CString};

/// Helper function for the sysfs `authenticated_show()`.
#[no_mangle]
pub unsafe extern "C" fn rust_authenticated_show(
    spdm_state: *mut SpdmState,
    buf: *mut core::ffi::c_char,
) -> isize {
    let state = unsafe { Box::from_raw(spdm_state) };

    let fmt = match CString::try_from_fmt(fmt!("{}\n", state.authenticated)) {
        Ok(f) => f,
        Err(_e) => return 0,
    };

    unsafe { bindings::sysfs_emit(buf, fmt.as_char_ptr()) as isize }
}
