// SPDX-License-Identifier: GPL-2.0
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! https://www.dmtf.org/dsp/DSP0274
//!
//! The `SpdmState` struct and implementation.
//!
//! Copyright (C) 2024 Western Digital

use core::ffi::c_void;
use core::slice::from_raw_parts_mut;
use kernel::prelude::*;
use kernel::{
    bindings,
    error::{code::EINVAL, to_result, Error},
    validate::Untrusted,
};

use crate::consts::{
    SpdmErrorCode, SPDM_ERROR, SPDM_GET_VERSION, SPDM_GET_VERSION_LEN, SPDM_MAX_VER, SPDM_MIN_VER,
    SPDM_REQ,
};
use crate::validator::{GetVersionReq, GetVersionRsp, SpdmErrorRsp, SpdmHeader};

/// The current SPDM session state for a device. Based on the
/// C `struct spdm_state`.
///
/// @dev: Responder device.  Used for error reporting and passed to @transport.
/// @transport: Transport function to perform one message exchange.
/// @transport_priv: Transport private data.
/// @transport_sz: Maximum message size the transport is capable of (in bytes).
///  Used as DataTransferSize in GET_CAPABILITIES exchange.
/// @keyring: Keyring against which to check the first certificate in
///  responder's certificate chain.
/// @validate: Function to validate additional leaf certificate requirements.
///
/// @version: Maximum common supported version of requester and responder.
///  Negotiated during GET_VERSION exchange.
///
/// @authenticated: Whether device was authenticated successfully.
#[allow(dead_code)]
pub struct SpdmState {
    pub(crate) dev: *mut bindings::device,
    pub(crate) transport: bindings::spdm_transport,
    pub(crate) transport_priv: *mut c_void,
    pub(crate) transport_sz: u32,
    pub(crate) keyring: *mut bindings::key,
    pub(crate) validate: bindings::spdm_validate,

    /* Negotiated state */
    pub(crate) version: u8,

    pub(crate) authenticated: bool,
}

impl SpdmState {
    pub(crate) fn new(
        dev: *mut bindings::device,
        transport: bindings::spdm_transport,
        transport_priv: *mut c_void,
        transport_sz: u32,
        keyring: *mut bindings::key,
        validate: bindings::spdm_validate,
    ) -> Self {
        SpdmState {
            dev,
            transport,
            transport_priv,
            transport_sz,
            keyring,
            validate,
            version: SPDM_MIN_VER,
            authenticated: false,
        }
    }

    fn spdm_err(&self, rsp: &SpdmErrorRsp) -> Result<(), Error> {
        let ret = match rsp.error_code {
            SpdmErrorCode::InvalidRequest => {
                pr_err!("Invalid request\n");
                bindings::EINVAL
            }
            SpdmErrorCode::InvalidSession => {
                if rsp.version == 0x11 {
                    pr_err!("Invalid session {:#x}\n", rsp.error_data);
                    bindings::EINVAL
                } else {
                    pr_err!("Undefined error {:#x}\n", rsp.error_code as u8);
                    bindings::EINVAL
                }
            }
            SpdmErrorCode::Busy => {
                pr_err!("Busy\n");
                bindings::EBUSY
            }
            SpdmErrorCode::UnexpectedRequest => {
                pr_err!("Unexpected request\n");
                bindings::EINVAL
            }
            SpdmErrorCode::Unspecified => {
                pr_err!("Unspecified error\n");
                bindings::EINVAL
            }
            SpdmErrorCode::DecryptError => {
                pr_err!("Decrypt error\n");
                bindings::EIO
            }
            SpdmErrorCode::UnsupportedRequest => {
                pr_err!("Unsupported request {:#x}\n", rsp.error_data);
                bindings::EINVAL
            }
            SpdmErrorCode::RequestInFlight => {
                pr_err!("Request in flight\n");
                bindings::EINVAL
            }
            SpdmErrorCode::InvalidResponseCode => {
                pr_err!("Invalid response code\n");
                bindings::EINVAL
            }
            SpdmErrorCode::SessionLimitExceeded => {
                pr_err!("Session limit exceeded\n");
                bindings::EBUSY
            }
            SpdmErrorCode::SessionRequired => {
                pr_err!("Session required\n");
                bindings::EINVAL
            }
            SpdmErrorCode::ResetRequired => {
                pr_err!("Reset required\n");
                bindings::ECONNRESET
            }
            SpdmErrorCode::ResponseTooLarge => {
                pr_err!("Response too large\n");
                bindings::EINVAL
            }
            SpdmErrorCode::RequestTooLarge => {
                pr_err!("Request too large\n");
                bindings::EINVAL
            }
            SpdmErrorCode::LargeResponse => {
                pr_err!("Large response\n");
                bindings::EMSGSIZE
            }
            SpdmErrorCode::MessageLost => {
                pr_err!("Message lost\n");
                bindings::EIO
            }
            SpdmErrorCode::InvalidPolicy => {
                pr_err!("Invalid policy\n");
                bindings::EINVAL
            }
            SpdmErrorCode::VersionMismatch => {
                pr_err!("Version mismatch\n");
                bindings::EINVAL
            }
            SpdmErrorCode::ResponseNotReady => {
                pr_err!("Response not ready\n");
                bindings::EINPROGRESS
            }
            SpdmErrorCode::RequestResynch => {
                pr_err!("Request resynchronization\n");
                bindings::ECONNRESET
            }
            SpdmErrorCode::OperationFailed => {
                pr_err!("Operation failed\n");
                bindings::EINVAL
            }
            SpdmErrorCode::NoPendingRequests => bindings::ENOENT,
            SpdmErrorCode::VendorDefinedError => {
                pr_err!("Vendor defined error\n");
                bindings::EINVAL
            }
        };

        to_result(-(ret as i32))
    }

    /// Start a SPDM exchange
    ///
    /// The data in `request_buf` is sent to the device and the response is
    /// stored in `response_buf`.
    pub(crate) fn spdm_exchange(
        &self,
        request_buf: &mut [u8],
        response_buf: &mut [u8],
    ) -> Result<i32, Error> {
        let header_size = core::mem::size_of::<SpdmHeader>();
        let request: &mut SpdmHeader = Untrusted::new_mut(request_buf).validate_mut()?;
        let response: &SpdmHeader = Untrusted::new_ref(response_buf).validate()?;

        let transport_function = self.transport.ok_or(EINVAL)?;
        let length = unsafe {
            transport_function(
                self.transport_priv,
                self.dev,
                request_buf.as_ptr() as *const c_void,
                request_buf.len(),
                response_buf.as_mut_ptr() as *mut c_void,
                response_buf.len(),
            ) as i32
        };
        to_result(length)?;

        if (length as usize) < header_size {
            return Ok(length); /* Truncated response is handled by callers */
        }
        if response.code == SPDM_ERROR {
            self.spdm_err(unsafe { &*(response_buf.as_ptr() as *const SpdmErrorRsp) })?;
        }

        if response.code != request.code & !SPDM_REQ {
            pr_err!(
                "Response code {:#x} does not match request code {:#x}\n",
                response.code,
                request.code
            );
            to_result(-(bindings::EPROTO as i32))?;
        }

        Ok(length)
    }

    /// Negoiate a supported SPDM version and store the information
    /// in the `SpdmState`.
    pub(crate) fn get_version(&mut self) -> Result<(), Error> {
        let mut request = GetVersionReq {
            version: self.version,
            code: SPDM_GET_VERSION,
            param1: 0,
            param2: 0,
        };
        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let request_buf = unsafe {
            from_raw_parts_mut(
                &mut request as *mut _ as *mut u8,
                core::mem::size_of::<GetVersionReq>(),
            )
        };

        let mut response_vec: Vec<u8> = Vec::with_capacity(SPDM_GET_VERSION_LEN, GFP_KERNEL)?;
        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let response_buf =
            unsafe { from_raw_parts_mut(response_vec.as_mut_ptr(), SPDM_GET_VERSION_LEN) };

        let rc = self.spdm_exchange(request_buf, response_buf)?;

        // SAFETY: `rc` bytes where inserted to the raw pointer by spdm_exchange
        unsafe { response_vec.set_len(rc as usize) };

        let response: &mut GetVersionRsp = Untrusted::new_mut(&mut response_vec).validate_mut()?;

        let mut foundver = false;
        for i in 0..response.version_number_entry_count {
            // Creating a reference on a packed stuct will result in
            // undefined behaviour, so we operate on the raw data directly
            let unaligned = core::ptr::addr_of_mut!(response.version_number_entries) as *mut u16;
            let addr = unaligned.wrapping_add(i as usize);
            let version = (unsafe { core::ptr::read_unaligned::<u16>(addr) } >> 8) as u8;

            if version >= self.version && version <= SPDM_MAX_VER {
                self.version = version;
                foundver = true;
            }
        }

        if !foundver {
            pr_err!("No common supported version\n");
            to_result(-(bindings::EPROTO as i32))?;
        }

        Ok(())
    }
}
