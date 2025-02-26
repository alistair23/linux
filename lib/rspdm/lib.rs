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
use core::pin::Pin;
use core::ptr;
use kernel::prelude::*;
use kernel::sync::{new_mutex, Mutex};
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
    // Wrap the `SpdmState` in a `Mutex` so that concurrent FFI callers (for
    // example, two threads racing on `spdm_authenticate()` for the same
    // device) serialize on the lock and never form aliased `&mut SpdmState`
    // references.
    let state = SpdmState::new(dev, transport, transport_priv, transport_sz, validate);
    match KBox::pin_init(new_mutex!(state), flags::GFP_KERNEL) {
        Ok(b) => {
            // `Mutex<SpdmState>` is `!Unpin` and must remain pinned in
            // memory.  The C side stores the raw pointer; `spdm_destroy()`
            // re-pins via `Pin::new_unchecked` before dropping, preserving
            // the pin invariant.
            // SAFETY: The contents are not moved between here and the
            // matching `KBox::from_raw` in `spdm_destroy()`.
            let raw = KBox::into_raw(unsafe { Pin::into_inner_unchecked(b) });
            raw as *mut spdm_state
        }
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

    // SAFETY: `state_ptr` was returned from `spdm_create()` (which leaks a
    // `Pin<KBox<Mutex<SpdmState>>>`) and has not yet been passed to
    // `spdm_destroy()`.  We only form a shared reference to the mutex; the
    // exclusive `&mut SpdmState` lives entirely inside the lock guard, so
    // concurrent FFI callers serialize on the mutex and can never form
    // aliased `&mut SpdmState` references.
    let mutex: &Mutex<SpdmState<'_>> = unsafe { &*(state_ptr as *const Mutex<SpdmState<'_>>) };

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

    // SAFETY: `state_ptr` was returned from `spdm_create()`, which leaked a
    // `Pin<KBox<Mutex<SpdmState>>>` via `KBox::into_raw`.  The caller
    // guarantees the state is no longer in use.  Reconstructing the pinned
    // box and dropping it runs `Drop` for the `Mutex` and `SpdmState` and
    // frees the allocation.
    let b = unsafe { KBox::from_raw(state_ptr as *mut Mutex<SpdmState<'_>>) };
    drop(unsafe { Pin::new_unchecked(b) });
}
