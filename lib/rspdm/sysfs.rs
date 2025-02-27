// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Western Digital

//! Rust sysfs helper functions
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use crate::SpdmState;
use kernel::prelude::*;
use kernel::{bindings, str::CString};

/// Helper function for the sysfs `authenticated_show()`.
#[no_mangle]
pub extern "C" fn rust_authenticated_show(spdm_state: *mut SpdmState, buf: *mut u8) -> isize {
    // SAFETY: The opaque pointer will be directly from the `spdm_create()`
    // function, so we can safely reconstruct it.
    let state = unsafe { KBox::from_raw(spdm_state) };

    let fmt = match CString::try_from_fmt(fmt!("{}\n", state.authenticated)) {
        Ok(f) => f,
        Err(_e) => return 0,
    };

    // SAFETY: Calling a kernel C function with valid arguments
    unsafe { bindings::sysfs_emit(buf, fmt.as_char_ptr()) as isize }
}
