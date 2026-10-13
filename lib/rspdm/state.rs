// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Western Digital

//! The `SpdmState` struct and implementation.
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use kernel::prelude::*;
use kernel::{
    bindings,
    device::{
        Bound,
        Device, //
    },
    error::Error,
    validate::Untrusted,
};

use crate::consts::{
    SPDM_ERROR,
    SPDM_GET_VERSION_LEN,
    SPDM_MAX_VER,
    SPDM_MIN_VER,
    SPDM_REQ, //
};
use crate::validator::{
    GetVersionReq,
    GetVersionRsp,
    SpdmErrorRsp,
    SpdmHeader, //
};

/// Transport for exchanging SPDM messages with a responder device.
///
/// This trait abstracts the bus-specific message transport (for example
/// a DOE mailbox for PCIe CMA) from the SPDM session logic.
pub(crate) trait Transport {
    /// Perform a single SPDM message exchange.
    ///
    /// Send `request` to the responder and write the response into
    /// `response`, returning the number of bytes received on success.
    fn exchange(
        &self,
        dev: &Device<Bound>,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, Error>;
}

/// The current SPDM session state for a device.
///
/// Concurrent access is serialised by wrapping the whole struct in a
/// `Mutex<SpdmState>` at the FFI boundary, so `spdm_authenticate()` callers
/// run one at a time and the locked `&mut SpdmState` is the only way to
/// reach the inner fields.
///
/// The lifetime `'a` is the duration for which the responder device and the
/// transport are guaranteed to stay alive, bounded by the responder device
/// staying bound to its driver.
///
/// `T` is data and an exchange function owned by the caller,
/// so the borrow checker enforces that the transport data outlives `SpdmState`.
#[expect(dead_code)]
pub(crate) struct SpdmState<'a, T: Transport> {
    /// Responder device. Used for error reporting and passed to `transport`.
    pub(crate) dev: &'a Device<Bound>,
    /// Transport used to perform message exchanges. Typically a `&'a`
    /// reference to transport data owned by the caller, which then must
    /// outlive the session.
    pub(crate) transport: T,
    /// Maximum message size the transport is capable of (in bytes). Used as
    /// DataTransferSize in GET_CAPABILITIES exchange.
    pub(crate) transport_sz: u32,
    /// Function to validate additional leaf certificate requirements.
    pub(crate) validate: bindings::spdm_validate,

    /// Maximum common supported version of requester and responder.
    /// Negotiated during GET_VERSION exchange.
    pub(crate) version: u8,
}

impl<'a, T: Transport> SpdmState<'a, T> {
    pub(crate) fn new(
        dev: &'a Device<Bound>,
        transport: T,
        transport_sz: u32,
        validate: bindings::spdm_validate,
    ) -> Self {
        SpdmState {
            dev,
            transport,
            transport_sz,
            validate,
            version: SPDM_MIN_VER,
        }
    }

    /// Start a SPDM exchange
    ///
    /// The data in `request_buf` is sent to the device and the response
    /// is returned as untrusted data to be validated by the caller.
    pub(crate) fn spdm_exchange(
        &self,
        request_buf: &[u8],
        mut response_buf: KVec<u8>,
    ) -> Result<Untrusted<KVec<u8>>, Error> {
        let header_size = core::mem::size_of::<SpdmHeader>();
        let request: SpdmHeader = Untrusted::new(request_buf).validate(self)?;

        let length = self
            .transport
            .exchange(self.dev, request_buf, response_buf.as_mut_slice())?;

        // The transport must not report more bytes than the buffer can hold.
        if length > response_buf.len() {
            pr_err!("Transport returned invalid length {length}\n");
            return Err(EMSGSIZE);
        }

        // Only validate the bytes actually received from the transport
        // Note that `length` might be longer then the actual SPDM packet as
        // some transports will pad the final message
        response_buf.truncate(length);

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

    /// Negotiate a supported SPDM version and store the information
    /// in the `SpdmState`.
    pub(crate) fn get_version(&mut self) -> Result<(), Error> {
        let mut request = GetVersionReq::default();
        request.header.version = SPDM_MIN_VER;
        self.version = SPDM_MIN_VER;

        let mut request_buf = request.to_bytes()?;

        let response_vec: KVec<u8> = KVec::from_elem(0u8, SPDM_GET_VERSION_LEN, GFP_KERNEL)?;

        let response: GetVersionRsp = self
            .spdm_exchange(request_buf.as_mut_slice(), response_vec)?
            .validate(&*self)?;

        let mut foundver = false;
        for &entry in response.version_number_entries.iter() {
            let alpha_version = (entry & 0xF) as u8;
            let version = (entry >> 8) as u8;

            if alpha_version != 0 {
                pr_warn!("Alpha version {alpha_version} is not specifically supported\n");
            }

            if version >= self.version && version <= SPDM_MAX_VER {
                self.version = version;
                foundver = true;
            }
        }

        if !foundver {
            pr_err!("No common supported version\n");
            return Err(EPROTO);
        }

        Ok(())
    }
}
