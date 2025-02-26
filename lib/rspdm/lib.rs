// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Western Digital

//! Top level library for SPDM
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>
//!
//! Top level library, including C compatible public functions to be called
//! from other subsytems.
//!
//! This mimics the C SPDM implementation in the kernel

use core::ffi::{c_int, c_void};
use core::ptr;
use core::slice::from_raw_parts_mut;
use kernel::prelude::*;
use kernel::{alloc::flags, bindings};

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
/// `keyring`: Trusted root certificates
/// `validate`: Function to validate additional leaf certificate requirements
///  (optional, may be %NULL)
///
/// Return a pointer to the allocated SPDM session state or NULL on error.
#[no_mangle]
pub unsafe extern "C" fn spdm_create(
    dev: *mut bindings::device,
    transport: bindings::spdm_transport,
    transport_priv: *mut c_void,
    transport_sz: u32,
    keyring: *mut bindings::key,
    validate: bindings::spdm_validate,
) -> *mut SpdmState {
    match KBox::new(
        SpdmState::new(
            dev,
            transport,
            transport_priv,
            transport_sz,
            keyring,
            validate,
        ),
        flags::GFP_KERNEL,
    ) {
        Ok(ret) => KBox::into_raw(ret) as *mut SpdmState,
        Err(_) => ptr::null_mut(),
    }
}

/// spdm_exchange() - Perform SPDM message exchange with device
///
/// @spdm_state: SPDM session state
/// @req: Request message
/// @req_sz: Size of @req
/// @rsp: Response message
/// @rsp_sz: Size of @rsp
///
/// Send the request @req to the device via the @transport in @spdm_state and
/// receive the response into @rsp, respecting the maximum buffer size @rsp_sz.
/// The request version is automatically populated.
///
/// Return response size on success or a negative errno.  Response size may be
/// less than @rsp_sz and the caller is responsible for checking that.  It may
/// also be more than expected (though never more than @rsp_sz), e.g. if the
/// transport receives only dword-sized chunks.
#[no_mangle]
pub unsafe extern "C" fn spdm_exchange(
    state: &'static mut SpdmState,
    req: *mut c_void,
    req_sz: usize,
    rsp: *mut c_void,
    rsp_sz: usize,
) -> isize {
    let request_buf: &mut [u8] = unsafe { from_raw_parts_mut(req as *mut u8, req_sz) };
    let response_buf: &mut [u8] = unsafe { from_raw_parts_mut(rsp as *mut u8, rsp_sz) };

    match state.spdm_exchange(request_buf, response_buf) {
        Ok(ret) => ret as isize,
        Err(e) => e.to_errno() as isize,
    }
}

/// spdm_authenticate() - Authenticate device
///
/// @spdm_state: SPDM session state
///
/// Authenticate a device through a sequence of GET_VERSION, GET_CAPABILITIES,
/// NEGOTIATE_ALGORITHMS, GET_DIGESTS, GET_CERTIFICATE and CHALLENGE exchanges.
///
/// Perform internal locking to serialize multiple concurrent invocations.
/// Can be called repeatedly for reauthentication.
///
/// Return 0 on success or a negative errno.  In particular, -EPROTONOSUPPORT
/// indicates authentication is not supported by the device.
#[no_mangle]
pub unsafe extern "C" fn spdm_authenticate(state: &'static mut SpdmState) -> c_int {
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

    let mut provisioned_slots = state.provisioned_slots;
    while (provisioned_slots as usize) > 0 {
        let slot = provisioned_slots.trailing_zeros() as u8;

        if let Err(e) = state.get_certificate(slot) {
            return e.to_errno() as c_int;
        }

        provisioned_slots &= !(1 << slot);
    }

    let mut provisioned_slots = state.provisioned_slots;
    while (provisioned_slots as usize) > 0 {
        let slot = provisioned_slots.trailing_zeros() as u8;

        if let Err(e) = state.validate_cert_chain(slot) {
            return e.to_errno() as c_int;
        }

        provisioned_slots &= !(1 << slot);
    }

    0
}

/// spdm_destroy() - Destroy SPDM session
///
/// @spdm_state: SPDM session state
#[no_mangle]
pub unsafe extern "C" fn spdm_destroy(state: &'static mut SpdmState) {
    if let Some(leaf_key) = &mut state.leaf_key {
        unsafe {
            bindings::public_key_free(*leaf_key);
        }
    }

    if let Some(desc) = &mut state.desc {
        unsafe {
            bindings::kfree(*desc as *mut _ as *mut c_void);
        }
    }

    unsafe {
        bindings::crypto_free_shash(state.shash);
    }
}
