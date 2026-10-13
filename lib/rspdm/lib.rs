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
use core::ptr;
use kernel::prelude::*;
use kernel::{
    alloc::flags,
    bindings,
    device::Device,
    error::to_result,
    ffi::{
        c_int,
        c_void, //
    },
    new_mutex,
    sync::Mutex,
    types::ForeignOwnable, //
};

use crate::consts::SPDM_MIN_DATA_TRANSFER_SIZE;
use crate::state::{
    SpdmState,
    Transport, //
};

const __LOG_PREFIX: &[u8] = b"spdm\0";

mod consts;
mod state;
mod validator;

/// FFI shim implementing [`Transport`] for C transport functions.
///
/// The private data pointer is owned by the C caller; see the safety
/// requirements of [`spdm_create()`].
struct CTransport {
    func: bindings::spdm_transport,
    priv_: *mut c_void,
}

impl Transport for CTransport {
    fn exchange(&self, dev: &Device, request: &[u8], response: &mut [u8]) -> Result<usize, Error> {
        let func = self.func.ok_or(EINVAL)?;

        // SAFETY: `func` is non-NULL as checked above. By the safety
        // requirements of `spdm_create()`, `priv_` remains valid until
        // `spdm_destroy()` is called, and `dev` remains alive for the
        // lifetime of the session (the session holds a device reference).
        // `request` and `response` are valid slices that outlive this call,
        // and the callback must not retain either of them.
        let length = unsafe {
            func(
                self.priv_,
                dev.as_raw(),
                request.as_ptr().cast::<c_void>(),
                request.len(),
                response.as_mut_ptr().cast::<c_void>(),
                response.len(),
            )
        };
        to_result(length)?;

        Ok(length as usize)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum SpdmErrorCode {
    InvalidRequest,
    /// This was removed in version 1.2.0 and is now reserved
    InvalidSession,
    Busy,
    UnexpectedRequest,
    Unspecified,
    DecryptError,
    UnsupportedRequest,
    RequestInFlight,
    InvalidResponseCode,
    SessionLimitExceeded,
    SessionRequired,
    ResetRequired,
    ResponseTooLarge,
    RequestTooLarge,
    LargeResponse,
    MessageLost,
    InvalidPolicy,
    VersionMismatch,
    ResponseNotReady,
    RequestResynch,
    OperationFailed,
    NoPendingRequests,
    RequestSessionTerminated,
    InvalidState,
    VendorDefinedError,
    /// Not a standard SPDM error code (e.g. from a future spec version).
    /// The raw code is kept for logging via the derived `Debug` impl.
    #[expect(dead_code)]
    Unknown(u8),
}

impl TryFrom<u8> for SpdmErrorCode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x01 => Self::InvalidRequest,
            0x02 => Self::InvalidSession,
            0x03 => Self::Busy,
            0x04 => Self::UnexpectedRequest,
            0x05 => Self::Unspecified,
            0x06 => Self::DecryptError,
            0x07 => Self::UnsupportedRequest,
            0x08 => Self::RequestInFlight,
            0x09 => Self::InvalidResponseCode,
            0x0a => Self::SessionLimitExceeded,
            0x0b => Self::SessionRequired,
            0x0c => Self::ResetRequired,
            0x0d => Self::ResponseTooLarge,
            0x0e => Self::RequestTooLarge,
            0x0f => Self::LargeResponse,
            0x10 => Self::MessageLost,
            0x11 => Self::InvalidPolicy,
            0x41 => Self::VersionMismatch,
            0x42 => Self::ResponseNotReady,
            0x43 => Self::RequestResynch,
            0x44 => Self::OperationFailed,
            0x45 => Self::NoPendingRequests,
            0x46 => Self::RequestSessionTerminated,
            0x47 => Self::InvalidState,
            0xff => Self::VendorDefinedError,
            v => Self::Unknown(v),
        })
    }
}

impl From<SpdmErrorCode> for Error {
    fn from(code: SpdmErrorCode) -> Self {
        match code {
            SpdmErrorCode::InvalidRequest => EINVAL,
            SpdmErrorCode::InvalidSession => EINVAL,
            SpdmErrorCode::Busy => EBUSY,
            SpdmErrorCode::UnexpectedRequest => EINVAL,
            SpdmErrorCode::Unspecified => EINVAL,
            SpdmErrorCode::DecryptError => EIO,
            SpdmErrorCode::UnsupportedRequest => EINVAL,
            SpdmErrorCode::RequestInFlight => EINVAL,
            SpdmErrorCode::InvalidResponseCode => EINVAL,
            SpdmErrorCode::SessionLimitExceeded => EBUSY,
            SpdmErrorCode::SessionRequired => EINVAL,
            SpdmErrorCode::ResetRequired => ECONNRESET,
            SpdmErrorCode::ResponseTooLarge => EINVAL,
            SpdmErrorCode::RequestTooLarge => EINVAL,
            SpdmErrorCode::LargeResponse => EMSGSIZE,
            SpdmErrorCode::MessageLost => EIO,
            SpdmErrorCode::InvalidPolicy => EINVAL,
            SpdmErrorCode::VersionMismatch => EINVAL,
            SpdmErrorCode::ResponseNotReady => EINPROGRESS,
            SpdmErrorCode::RequestResynch => ECONNRESET,
            SpdmErrorCode::OperationFailed => EINVAL,
            SpdmErrorCode::NoPendingRequests => ENOENT,
            SpdmErrorCode::RequestSessionTerminated => EINVAL,
            SpdmErrorCode::InvalidState => EINVAL,
            SpdmErrorCode::VendorDefinedError => EINVAL,
            SpdmErrorCode::Unknown(_) => EPROTO,
        }
    }
}

/// Allocates an SPDM session.
///
/// See `include/linux/spdm.h` for the full C API documentation.
///
/// # Safety
///
/// The caller must guarantee that `dev` is a valid, non-NULL pointer to a
/// `struct device` with a live reference count. The session takes its own
/// reference, so the device does not need to stay bound to its driver for
/// the session's lifetime. The caller must also guarantee that
/// `transport_priv` remains valid until `spdm_destroy()` is called, as it
/// is passed back to `transport` on each exchange.
#[export]
pub unsafe extern "C" fn spdm_create(
    dev: *mut bindings::device,
    transport: bindings::spdm_transport,
    transport_priv: *mut c_void,
    transport_sz: u32,
    validate: bindings::spdm_validate,
) -> *mut spdm_state {
    if dev.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: By the safety requirements of this function, `dev` is a valid
    // pointer to a `struct device` with a live reference count, so a new
    // reference can be taken.
    let dev = unsafe { Device::get_device(dev) };

    if transport_sz < SPDM_MIN_DATA_TRANSFER_SIZE {
        dev_err!(
            &dev,
            "Transfer size {transport_sz} below SPDM minimum {SPDM_MIN_DATA_TRANSFER_SIZE}\n"
        );
        return ptr::null_mut();
    }

    // Wrap the `SpdmState` in a `Mutex` so that concurrent FFI callers (for
    // example, two threads racing on `spdm_authenticate()` for the same
    // device) serialize on the lock and never form aliased `&mut SpdmState`
    // references.
    let state = SpdmState::new(
        dev,
        CTransport {
            func: transport,
            priv_: transport_priv,
        },
        transport_sz,
        validate,
    );
    match KBox::pin_init(new_mutex!(state), flags::GFP_KERNEL) {
        Ok(b) => b.into_foreign().cast::<spdm_state>(),
        Err(_) => ptr::null_mut(),
    }
}

/// Authenticates a device through a sequence of SPDM exchanges.
///
/// See `include/linux/spdm.h` for the full C API documentation.
///
/// # Safety
///
/// `state_ptr` must be a valid pointer returned by a previous call to
/// `spdm_create()` that has not yet been passed to `spdm_destroy()`.
#[export]
pub unsafe extern "C" fn spdm_authenticate(state_ptr: *mut spdm_state) -> c_int {
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
        <Pin<KBox<Mutex<SpdmState<CTransport>>>> as ForeignOwnable>::borrow(
            state_ptr.cast::<c_void>(),
        )
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

    if state.provisioned_slots == 0 {
        return -(bindings::EIO as c_int);
    }

    let mut provisioned_slots = state.provisioned_slots;
    while (provisioned_slots as usize) > 0 {
        let slot = provisioned_slots.trailing_zeros() as u8;

        if let Err(e) = state.get_certificate(slot) {
            return e.to_errno() as c_int;
        }

        provisioned_slots &= !(1 << slot);
    }

    -(EPROTONOSUPPORT as i32)
}

/// Destroys an SPDM session.
///
/// See `include/linux/spdm.h` for the full C API documentation.
///
/// # Safety
///
/// `state_ptr` must have been returned by a previous call to
/// `spdm_create()` and must not be passed to this function more than once.
#[export]
pub unsafe extern "C" fn spdm_destroy(state_ptr: *mut spdm_state) {
    if state_ptr.is_null() {
        return;
    }

    // SAFETY: `state_ptr` was returned from `spdm_create()` which used
    // `into_foreign()` to create the pointer.
    let mutex = unsafe {
        <Pin<KBox<Mutex<SpdmState<CTransport>>>> as ForeignOwnable>::from_foreign(
            state_ptr.cast::<c_void>(),
        )
    };

    drop(mutex);
}
