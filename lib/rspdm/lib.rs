// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Western Digital

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
    bindings,
    new_mutex,
    sync::Mutex,
    types::ForeignOwnable, //
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
    // Wrap the `SpdmState` in a `Mutex` so that concurrent FFI callers (for
    // example, two threads racing on `spdm_authenticate()` for the same
    // device) serialize on the lock and never form aliased `&mut SpdmState`
    // references.
    let state = SpdmState::new(dev, transport, transport_priv, transport_sz, validate);
    match KBox::pin_init(new_mutex!(state), flags::GFP_KERNEL) {
        Ok(b) => b.into_foreign() as *mut spdm_state,
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
pub extern "C" fn spdm_authenticate(state_ptr: *mut spdm_state) -> c_int {
    if state_ptr.is_null() {
        return -(bindings::EINVAL as c_int);
    }

    // SAFETY: `state_ptr` was returned from `spdm_create()` which used `into_foreign()`
    // to create the pointer, and it remains valid until `spdm_destroy()` is called.
    // We only borrow here (rather than `from_foreign()`) so that ownership stays
    // with the foreign (C) caller.
    // The exclusive `&mut SpdmState` lives entirely inside the lock guard, so
    // concurrent FFI callers serialize on the mutex and can never form
    // aliased `&mut SpdmState` references.
    let mutex = unsafe {
        <Pin<KBox<Mutex<SpdmState<'_>>>> as ForeignOwnable>::borrow(state_ptr as *mut c_void)
    };

    let mut state = mutex.lock();

    if let Err(e) = state.get_version() {
        return e.to_errno() as c_int;
    }

    if let Err(e) = state.get_capabilities() {
        return e.to_errno() as c_int;
    }

    if let Err(e) = state.negotiate_algs() {
        return e.to_errno() as c_int;
    }

    if let Err(e) = state.get_digests() {
        return e.to_errno() as c_int;
    }

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

    // SAFETY: `state_ptr` was returned from `spdm_create()` which used `into_foreign()`
    // to create the pointer.
    let mutex: KBox<Mutex<SpdmState<'_>>> = unsafe { KBox::from_foreign(state_ptr as *mut c_void) };

    drop(mutex);
}
