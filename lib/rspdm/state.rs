// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Western Digital

//! The `SpdmState` struct and implementation.
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use core::ffi::c_void;
use kernel::prelude::*;
use kernel::{
    bindings,
    device::{
        Bound,
        Device, //
    },
    error::{
        code::EINVAL,
        to_result,
        Error, //
    },
    validate::Untrusted,
};

use crate::consts::{
    SPDM_ERROR,
    SPDM_MIN_VER,
    SPDM_REQ, //
};
use crate::validator::{
    SpdmErrorRsp,
    SpdmHeader, //
};

/// The current SPDM session state for a device.
///
/// Concurrent access is serialised by wrapping the whole struct in a
/// `Mutex<SpdmState>` at the FFI boundary, so `spdm_authenticate()` callers
/// run one at a time and the locked `&mut SpdmState` is the only way to
/// reach the inner fields.
///
/// The lifetime `'a` is the duration for which the responder device is
/// guaranteed to stay alive and bound to its driver.
#[expect(dead_code)]
pub(crate) struct SpdmState<'a> {
    /// Responder device. Used for error reporting and passed to `transport`.
    pub(crate) dev: &'a Device<Bound>,
    /// Transport function to perform one message exchange.
    pub(crate) transport: bindings::spdm_transport,
    /// Transport private data.
    pub(crate) transport_priv: *mut c_void,
    /// Maximum message size the transport is capable of (in bytes). Used as
    /// DataTransferSize in GET_CAPABILITIES exchange.
    pub(crate) transport_sz: u32,
    /// Function to validate additional leaf certificate requirements.
    pub(crate) validate: bindings::spdm_validate,

    /// Maximum common supported version of requester and responder.
    /// Negotiated during GET_VERSION exchange.
    pub(crate) version: u8,
}

impl<'a> SpdmState<'a> {
    pub(crate) fn new(
        dev: &'a Device<Bound>,
        transport: bindings::spdm_transport,
        transport_priv: *mut c_void,
        transport_sz: u32,
        validate: bindings::spdm_validate,
    ) -> Self {
        SpdmState {
            dev,
            transport,
            transport_priv,
            transport_sz,
            validate,
            version: SPDM_MIN_VER,
        }
    }

    /// Start a SPDM exchange
    ///
    /// The data in `request_buf` is sent to the device and the response
    /// is returned as untrusted data to be validated by the caller.
    #[allow(dead_code)]
    pub(crate) fn spdm_exchange(
        &self,
        request_buf: &[u8],
        mut response_buf: KVec<u8>,
    ) -> Result<Untrusted<KVec<u8>>, Error> {
        let header_size = core::mem::size_of::<SpdmHeader>();
        let request: SpdmHeader = Untrusted::new(request_buf).validate(self)?;

        let transport_function = self.transport.ok_or(EINVAL)?;
        // SAFETY: `transport_function` is provided by the new(), we are
        // calling the function.
        // The device remains alive and bound for the lifetime of the
        // session as guaranteed by the ABI contract. So the pointer obtained
        // from `self.dev` is valid for this call and `transport_function`
        //  must not retain it.
        // We have a immutable reference to request_buf above, and pass
        // another reference here.
        // We don't have any references to the mutable response_buf
        let length = unsafe {
            transport_function(
                self.transport_priv,
                self.dev.as_raw(),
                request_buf.as_ptr().cast::<c_void>(),
                request_buf.len(),
                response_buf.as_mut_ptr().cast::<c_void>(),
                response_buf.len(),
            )
        };
        to_result(length)?;

        // The transport must not report more bytes than the buffer can hold.
        if length as usize > response_buf.len() {
            pr_err!("Transport returned invalid length {length}\n");
            return Err(EMSGSIZE);
        }

        // Only validate the bytes actually received from the transport
        // Note that `length` might be longer then the actual SPDM packet as
        // some transports will pad the final message
        response_buf.truncate(length as usize);

        let response: SpdmHeader =
            Untrusted::new(response_buf.get(..header_size).ok_or(EPROTO)?).validate(self)?;

        if response.code == SPDM_ERROR {
            let error_rsp: SpdmErrorRsp =
                Untrusted::new(response_buf.get(..header_size).ok_or(EPROTO)?).validate(self)?;
            pr_err!("Error response: {error_rsp:?}\n");
            return Err(error_rsp.error_code.into());
        }

        if response.code != request.code & !SPDM_REQ {
            pr_err!(
                "Response code {:#x} does not match request code {:#x}\n",
                response.code,
                request.code
            );
            return Err(EPROTO);
        }

        Ok(Untrusted::new(response_buf))
    }
}
