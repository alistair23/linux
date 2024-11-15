// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Western Digital

//! Top level library for SPDM
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>
//!
//! Top level library, including C compatible public functions to be called
//! from other subsytems.

use crate::bindings::{
    spdm_state,
    EPROTONOSUPPORT, //
};
use core::ffi::{
    c_int,
    c_void, //
};
use core::ptr;
use kernel::prelude::*;
use kernel::{
    alloc::flags,
    bindings, //
};

use crate::state::SpdmState;

const __LOG_PREFIX: &[u8] = b"spdm\0";

mod consts;
mod state;
mod validator;

/// spdm_create() - Allocate SPDM session
///
/// `dev`: Responder device
/// `transport`: Transport function to perform one message exchange
/// `transport_priv`: Transport private data
/// `transport_sz`: Maximum message size the transport is capable of (in bytes)
/// `validate`: Function to validate additional leaf certificate requirements
///  (optional, may be %NULL)
///
/// Return a pointer to the allocated SPDM session state or NULL on error.
#[export]
pub extern "C" fn spdm_create(
    dev: *mut bindings::device,
    transport: bindings::spdm_transport,
    transport_priv: *mut c_void,
    transport_sz: u32,
    validate: bindings::spdm_validate,
) -> *mut spdm_state {
    match KBox::new(
        SpdmState::new(dev, transport, transport_priv, transport_sz, validate),
        flags::GFP_KERNEL,
    ) {
        Ok(ret) => KBox::into_raw(ret) as *mut spdm_state,
        Err(_) => ptr::null_mut(),
    }
}

/// spdm_authenticate() - Authenticate device
///
/// @spdm_state: SPDM session state
///
/// Authenticate a device through a sequence of GET_VERSION, GET_CAPABILITIES,
/// NEGOTIATE_ALGORITHMS, GET_DIGESTS, GET_CERTIFICATE and CHALLENGE exchanges.
///
/// Return 0 on success or a negative errno.  In particular, -EPROTONOSUPPORT
/// indicates authentication is not supported by the device.
#[export]
pub extern "C" fn spdm_authenticate(_state_ptr: *mut spdm_state) -> c_int {
    -(EPROTONOSUPPORT as i32)
}

/// spdm_destroy() - Destroy SPDM session
///
/// @spdm_state: SPDM session state
#[export]
pub extern "C" fn spdm_destroy(state_ptr: *mut spdm_state) {
    if state_ptr.is_null() {
        return;
    }
    // SAFETY: `state_ptr` was returned from `spdm_create` (which uses
    // `KBox::into_raw`) and the caller guarantees the state is no longer
    // in use.  Reconstructing the `KBox` and dropping it frees the state.
    drop(unsafe { KBox::from_raw(state_ptr as *mut SpdmState) });
}
