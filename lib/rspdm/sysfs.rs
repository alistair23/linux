// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Western Digital

//! Rust sysfs helper functions
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use crate::SpdmState;
use core::slice::from_raw_parts;
use kernel::prelude::*;
use kernel::{bindings, str::CString};

/// Helper function for the sysfs `authenticated_show()`.
#[no_mangle]
pub extern "C" fn rust_authenticated_show(spdm_state: *mut SpdmState, buf: *mut u8) -> isize {
    // SAFETY: The opaque pointer will be directly from the `spdm_create()`
    // function, so we can safely dereference it.
    let state = unsafe { &*spdm_state };

    let fmt = match CString::try_from_fmt(fmt!("{}\n", state.authenticated)) {
        Ok(f) => f,
        Err(_e) => return 0,
    };

    // SAFETY: Calling a kernel C function with valid arguments
    unsafe { bindings::sysfs_emit(buf, fmt.as_char_ptr()) as isize }
}

/// Helper function to trigger a SPDM challenge
#[no_mangle]
pub unsafe extern "C" fn spdm_chall(state: &'static mut SpdmState) -> c_int {
    if let Err(e) = state.challenge(state.provisioned_slots.trailing_zeros() as u8, false) {
        return e.to_errno() as c_int;
    }

    0
}

/// Helper function for the sysfs `nonce_store()`.
#[no_mangle]
pub extern "C" fn spdm_nonce_store(
    spdm_state: *mut SpdmState,
    buf: *const u8,
    off: i64,
    count: usize,
) -> isize {
    // SAFETY: The opaque pointer will be directly from the `spdm_create()`
    // function, so we can safely dereference it.
    let state = unsafe { &mut *spdm_state };
    // SAFETY: `buf` is count bytes, initialised, aligned and won't be mutated
    let slice = unsafe { from_raw_parts(buf, count) };
    let capacity = state.next_nonce.capacity();
    let end = off as usize + count;

    if end > capacity {
        if let Err(_) = state.next_nonce.extend_with(end - capacity, 0, GFP_KERNEL) {
            return -(bindings::ENOMEM as isize);
        }
    }

    state.next_nonce.as_mut_slice()[(off as usize)..end].copy_from_slice(slice);

    count as isize
}

/// Helper function for the sysfs `nonce_show()`.
#[no_mangle]
pub extern "C" fn spdm_nonce_show(
    spdm_state: *mut SpdmState,
    buf: *mut u8,
    off: i64,
    count: usize,
) -> isize {
    // SAFETY: The opaque pointer will be directly from the `spdm_create()`
    // function, so we can safely dereference it.
    let state = unsafe { &*spdm_state };
    let nonce = state.next_nonce.as_slice();

    if off as usize >= nonce.len() {
        return 0;
    }

    let remaining = &nonce[off as usize..];
    let len = core::cmp::min(remaining.len(), count);

    // SAFETY: buf is at least count bytes, remaining is at least len bytes
    unsafe { core::ptr::copy_nonoverlapping(remaining.as_ptr(), buf, len) };

    len as isize
}

/// Return a pointer and length for the certificate chain in the given slot.
/// Returns 0 length if the slot has no certificate.
#[no_mangle]
pub extern "C" fn spdm_get_cert(
    spdm_state: *const SpdmState,
    slot: u8,
    out_data: *mut *const u8,
    out_len: *mut usize,
) {
    // SAFETY: The opaque pointer will be directly from the `spdm_create()`
    // function, so we can safely dereference it.
    let state = unsafe { &*spdm_state };
    if slot as usize >= crate::consts::SPDM_SLOTS || state.certs[slot as usize].is_empty() {
        unsafe {
            *out_data = core::ptr::null();
            *out_len = 0;
        }
    } else {
        unsafe {
            *out_data = state.certs[slot as usize].as_ptr();
            *out_len = state.certs[slot as usize].len();
        }
    }
}

/// Return a pointer and length for the VCA (version/capabilities/algorithms) transcript.
/// This is the portion of the SPDM transcript before the CHALLENGE exchange.
#[no_mangle]
pub extern "C" fn spdm_get_transcript(
    spdm_state: *const SpdmState,
    out_data: *mut *const u8,
    out_len: *mut usize,
) {
    // SAFETY: The opaque pointer will be directly from the `spdm_create()`
    // function, so we can safely dereference it.
    let state = unsafe { &*spdm_state };
    let len = state.transcript.len();
    unsafe {
        *out_data = state.transcript.as_ptr();
        *out_len = len;
    }
}
