// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Western Digital

//! The `SpdmState` struct and implementation.
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use core::ffi::c_void;
use core::slice::from_raw_parts_mut;
use kernel::prelude::*;
use kernel::{
    bindings,
    error::{
        code::EINVAL,
        from_err_ptr,
        to_result,
        Error, //
    },
    str::CStr,
    validate::Untrusted,
};

use crate::consts::{
    SpdmErrorCode,
    SPDM_ASYM_ALGOS,
    SPDM_ASYM_ECDSA_ECC_NIST_P256,
    SPDM_ASYM_ECDSA_ECC_NIST_P384,
    SPDM_ASYM_ECDSA_ECC_NIST_P521,
    SPDM_ASYM_RSASSA_2048,
    SPDM_ASYM_RSASSA_3072,
    SPDM_ASYM_RSASSA_4096,
    SPDM_ERROR,
    SPDM_GET_VERSION_LEN,
    SPDM_HASH_ALGOS,
    SPDM_HASH_SHA_256,
    SPDM_HASH_SHA_384,
    SPDM_HASH_SHA_512,
    SPDM_KEY_EX_CAP,
    SPDM_MAX_VER,
    SPDM_MIN_DATA_TRANSFER_SIZE,
    SPDM_MIN_VER,
    SPDM_OPAQUE_DATA_FMT_GENERAL,
    SPDM_REQ,
    SPDM_RSP_MIN_CAPS,
    SPDM_SLOTS,
    SPDM_VER_10,
    SPDM_VER_11,
    SPDM_VER_12,
    SPDM_VER_13, //
};
use crate::validator::{
    GetCapabilitiesReq,
    GetCapabilitiesRsp,
    GetDigestsReq,
    GetDigestsRsp,
    GetVersionReq,
    GetVersionRsp,
    NegotiateAlgsReq,
    NegotiateAlgsRsp,
    SpdmErrorRsp,
    SpdmHeader, //
};

/// The current SPDM session state for a device. Based on the
/// C `struct spdm_state`.
///
/// Concurrent access is serialized by wrapping the whole struct in a
/// `Mutex<SpdmState>` at the FFI boundary, so `spdm_authenticate()` callers
/// run one at a time and the locked `&mut SpdmState` is the only way to
/// reach the inner fields.
///
/// `dev`: Responder device.  Used for error reporting and passed to @transport.
/// `transport`: Transport function to perform one message exchange.
/// `transport_priv`: Transport private data.
/// `transport_sz`: Maximum message size the transport is capable of (in bytes).
///  Used as DataTransferSize in GET_CAPABILITIES exchange.
/// `validate`: Function to validate additional leaf certificate requirements.
///
/// `version`: Maximum common supported version of requester and responder.
///  Negotiated during GET_VERSION exchange.
/// `rsp_caps`: Cached capabilities of responder.
///  Received during GET_CAPABILITIES exchange.
/// @base_asym_alg: Asymmetric key algorithm for signature verification of
///  CHALLENGE_AUTH and MEASUREMENTS messages.
///  Selected by responder during NEGOTIATE_ALGORITHMS exchange.
/// @base_hash_alg: Hash algorithm for signature verification of
///  CHALLENGE_AUTH and MEASUREMENTS messages.
///  Selected by responder during NEGOTIATE_ALGORITHMS exchange.
/// @meas_hash_alg: Hash algorithm for measurement blocks.
///  Selected by responder during NEGOTIATE_ALGORITHMS exchange.
/// @supported_slots: Bitmask of responder's supported certificate slots.
///  Received during GET_DIGESTS exchange (from SPDM 1.3).
/// @provisioned_slots: Bitmask of responder's provisioned certificate slots.
///  Received during GET_DIGESTS exchange.
/// @base_asym_enc: Human-readable name of @base_asym_alg's signature encoding.
///  Passed to crypto subsystem when calling verify_signature().
/// @sig_len: Signature length of @base_asym_alg (in bytes).
///  S or SigLen in SPDM specification.
/// @base_hash_alg_name: Human-readable name of @base_hash_alg.
///  Passed to crypto subsystem when calling crypto_alloc_shash() and
///  verify_signature().
/// @shash: Synchronous hash handle for @base_hash_alg computation.
/// @desc: Synchronous hash context for @base_hash_alg computation.
/// @hash_len: Hash length of @base_hash_alg (in bytes).
///  H in SPDM specification.
/// @certs: Certificate chain in each of the 8 slots. Empty KVec if a slot is
///  not populated. Prefixed by the 4 + H header per SPDM 1.0.0 table 15.
#[expect(dead_code)]
pub(crate) struct SpdmState<'a> {
    pub(crate) dev: *mut bindings::device,
    pub(crate) transport: bindings::spdm_transport,
    pub(crate) transport_priv: *mut c_void,
    pub(crate) transport_sz: u32,
    pub(crate) validate: bindings::spdm_validate,

    // Negotiated state
    pub(crate) version: u8,
    pub(crate) rsp_caps: u32,
    pub(crate) base_asym_alg: u32,
    pub(crate) base_hash_alg: u32,
    pub(crate) meas_hash_alg: u32,
    pub(crate) supported_slots: u8,
    pub(crate) provisioned_slots: u8,

    /* Signature algorithm */
    base_asym_enc: &'a CStr,
    sig_len: usize,

    /* Hash algorithm */
    base_hash_alg_name: &'a CStr,
    pub(crate) shash: *mut bindings::crypto_shash,
    pub(crate) desc: Option<&'a mut bindings::shash_desc>,
    pub(crate) hash_len: usize,

    // Certificates
    pub(crate) certs: [KVec<u8>; SPDM_SLOTS],
}

impl Drop for SpdmState<'_> {
    fn drop(&mut self) {
        if let Some(desc) = self.desc.take() {
            // SAFETY: `self.shash` is a valid handle
            let desc_len = core::mem::size_of::<bindings::shash_desc>()
                + unsafe { bindings::crypto_shash_descsize(self.shash) } as usize;

            // SAFETY: `desc` was allocated as a KVec<u8> with a length of `desc_len`
            // and then transmuted to a raw pointer with into_raw_parts()
            let desc_ptr =
                unsafe { core::mem::transmute::<&mut bindings::shash_desc, *mut u8>(desc) };
            let desc_vec = unsafe { KVec::<u8>::from_raw_parts(desc_ptr, desc_len, desc_len) };
            drop(desc_vec);
        }

        unsafe {
            bindings::crypto_free_shash(self.shash);
        }
    }
}

impl SpdmState<'_> {
    pub(crate) fn new(
        dev: *mut bindings::device,
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
            rsp_caps: 0,
            base_asym_alg: 0,
            base_hash_alg: 0,
            meas_hash_alg: 0,
            supported_slots: 0,
            provisioned_slots: 0,
            base_asym_enc: unsafe { CStr::from_bytes_with_nul_unchecked(b"\0") },
            sig_len: 0,
            base_hash_alg_name: unsafe { CStr::from_bytes_with_nul_unchecked(b"\0") },
            shash: core::ptr::null_mut(),
            desc: None,
            hash_len: 0,
            certs: [const { KVec::new() }; SPDM_SLOTS],
        }
    }

    fn spdm_err(&self, rsp: &SpdmErrorRsp) -> Result<(), Error> {
        match rsp.error_code {
            SpdmErrorCode::InvalidRequest => {
                pr_err!("Invalid request\n");
                Err(EINVAL)
            }
            SpdmErrorCode::InvalidSession => {
                if rsp.version == 0x11 {
                    pr_err!("Invalid session {:#x}\n", rsp.error_data);
                    Err(EINVAL)
                } else {
                    pr_err!("Undefined error {:#x}\n", rsp.error_code);
                    Err(EINVAL)
                }
            }
            SpdmErrorCode::Busy => {
                pr_err!("Busy\n");
                Err(EBUSY)
            }
            SpdmErrorCode::UnexpectedRequest => {
                pr_err!("Unexpected request\n");
                Err(EINVAL)
            }
            SpdmErrorCode::Unspecified => {
                pr_err!("Unspecified error\n");
                Err(EINVAL)
            }
            SpdmErrorCode::DecryptError => {
                pr_err!("Decrypt error\n");
                Err(EIO)
            }
            SpdmErrorCode::UnsupportedRequest => {
                pr_err!("Unsupported request {:#x}\n", rsp.error_data);
                Err(EINVAL)
            }
            SpdmErrorCode::RequestInFlight => {
                pr_err!("Request in flight\n");
                Err(EINVAL)
            }
            SpdmErrorCode::InvalidResponseCode => {
                pr_err!("Invalid response code\n");
                Err(EINVAL)
            }
            SpdmErrorCode::SessionLimitExceeded => {
                pr_err!("Session limit exceeded\n");
                Err(EBUSY)
            }
            SpdmErrorCode::SessionRequired => {
                pr_err!("Session required\n");
                Err(EINVAL)
            }
            SpdmErrorCode::ResetRequired => {
                pr_err!("Reset required\n");
                Err(ECONNRESET)
            }
            SpdmErrorCode::ResponseTooLarge => {
                pr_err!("Response too large\n");
                Err(EINVAL)
            }
            SpdmErrorCode::RequestTooLarge => {
                pr_err!("Request too large\n");
                Err(EINVAL)
            }
            SpdmErrorCode::LargeResponse => {
                pr_err!("Large response\n");
                Err(EMSGSIZE)
            }
            SpdmErrorCode::MessageLost => {
                pr_err!("Message lost\n");
                Err(EIO)
            }
            SpdmErrorCode::InvalidPolicy => {
                pr_err!("Invalid policy\n");
                Err(EINVAL)
            }
            SpdmErrorCode::VersionMismatch => {
                pr_err!("Version mismatch\n");
                Err(EINVAL)
            }
            SpdmErrorCode::ResponseNotReady => {
                pr_err!("Response not ready\n");
                Err(EINPROGRESS)
            }
            SpdmErrorCode::RequestResynch => {
                pr_err!("Request resynchronization\n");
                Err(ECONNRESET)
            }
            SpdmErrorCode::OperationFailed => {
                pr_err!("Operation failed\n");
                Err(EINVAL)
            }
            SpdmErrorCode::NoPendingRequests => Err(ENOENT),
            SpdmErrorCode::VendorDefinedError => {
                pr_err!("Vendor defined error\n");
                Err(EINVAL)
            }
            SpdmErrorCode::RequestSessionTerminated => {
                pr_err!("Request session terminated\n");
                Err(EINVAL)
            }
            SpdmErrorCode::InvalidState => {
                pr_err!("Invalid State\n");
                Err(EINVAL)
            }
        }
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
        let request: &SpdmHeader = Untrusted::new(&request_buf[..]).validate()?;

        let transport_function = self.transport.ok_or(EINVAL)?;
        // SAFETY: `transport_function` is provided by the new(), we are
        // calling the function.
        // We have a immutable reference to request_buf above, and pass
        // another reference here.
        // We don't have any references to the mutable response_buf
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
            return Ok(length); // Truncated response is handled by callers
        }

        let response: &SpdmHeader = Untrusted::new(&response_buf[..]).validate()?;

        if response.code == SPDM_ERROR {
            let error_rsp: &SpdmErrorRsp =
                Untrusted::new(&response_buf[..header_size as usize]).validate()?;
            self.spdm_err(error_rsp)?;
        }

        if response.code != request.code & !SPDM_REQ {
            pr_err!(
                "Response code {:#x} does not match request code {:#x}\n",
                response.code,
                request.code
            );
            return Err(EPROTO);
        }

        Ok(length)
    }

    /// Negotiate a supported SPDM version and store the information
    /// in the `SpdmState`.
    pub(crate) fn get_version(&mut self) -> Result<(), Error> {
        let mut request = GetVersionReq::default();
        request.version = SPDM_MIN_VER;
        self.version = SPDM_MIN_VER;

        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let request_buf = unsafe {
            from_raw_parts_mut(
                &mut request as *mut _ as *mut u8,
                core::mem::size_of::<GetVersionReq>(),
            )
        };

        let mut response_vec: KVec<u8> = KVec::from_elem(0u8, SPDM_GET_VERSION_LEN, GFP_KERNEL)?;

        let rc = self.spdm_exchange(request_buf, response_vec.as_mut_slice())? as usize;

        // The transport must report a length within the buffer we provided.
        if rc > response_vec.len() {
            return Err(EINVAL);
        }
        response_vec.truncate(rc);

        let response: &GetVersionRsp = Untrusted::new(response_vec.as_slice()).validate()?;

        let mut foundver = false;
        let entry_count = response.version_number_entry_count;
        let entries_offset = core::mem::offset_of!(GetVersionRsp, version_number_entries);

        for i in 0..entry_count as usize {
            let off = entries_offset + i * core::mem::size_of::<u16>();
            let entry = u16::from_le_bytes([response_vec[off], response_vec[off + 1]]);
            let alpha_version = (entry & 0xF) as u8;
            let version = (entry >> 8) as u8;

            if alpha_version > 0 {
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

    /// Obtain the supported capabilities from an SPDM session and store the
    /// information in the `SpdmState`.
    pub(crate) fn get_capabilities(&mut self) -> Result<(), Error> {
        let mut request = GetCapabilitiesReq::default();
        request.version = self.version;

        let (req_sz, rsp_sz) = match self.version {
            SPDM_VER_10 => (
                core::mem::size_of::<SpdmHeader>(),
                core::mem::size_of::<SpdmHeader>() + 4 + core::mem::size_of::<u32>(),
            ),
            SPDM_VER_11 => {
                let len = core::mem::size_of::<SpdmHeader>() + 4 + core::mem::size_of::<u32>();
                (len, len)
            }
            _ => {
                request.data_transfer_size = self.transport_sz.to_le();
                request.max_spdm_msg_size = request.data_transfer_size;

                (
                    core::mem::size_of::<GetCapabilitiesReq>(),
                    core::mem::size_of::<GetCapabilitiesRsp>(),
                )
            }
        };

        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let request_buf = unsafe { from_raw_parts_mut(&mut request as *mut _ as *mut u8, req_sz) };

        let mut response_vec: KVec<u8> = KVec::from_elem(0u8, rsp_sz, GFP_KERNEL)?;

        let rc = self.spdm_exchange(request_buf, response_vec.as_mut_slice())? as usize;

        // The transport must report a length within the buffer we provided.
        if rc > response_vec.len() {
            pr_err!("Overflowed capabilities response\n");
            return Err(EIO);
        }
        response_vec.truncate(rc);

        let response: &mut GetCapabilitiesRsp = Untrusted::new(&mut response_vec).validate()?;

        self.rsp_caps = u32::from_le(response.flags);
        if (self.rsp_caps & SPDM_RSP_MIN_CAPS) != SPDM_RSP_MIN_CAPS {
            pr_err!(
                "{:#x} capabilities are supported, which don't meet required {:#x}\n",
                self.rsp_caps,
                SPDM_RSP_MIN_CAPS
            );
            self.rsp_caps = 0;
            return Err(EPROTONOSUPPORT);
        }

        if self.version >= SPDM_VER_12 {
            let data_transfer_size = u32::from_le(response.data_transfer_size);
            if data_transfer_size < SPDM_MIN_DATA_TRANSFER_SIZE {
                pr_err!("Malformed capabilities response\n");
                return Err(EPROTO);
            }
            self.transport_sz = self.transport_sz.min(data_transfer_size);
        }

        Ok(())
    }

    fn update_response_algs(&mut self) -> Result<(), Error> {
        match self.base_asym_alg {
            SPDM_ASYM_RSASSA_2048 => {
                self.sig_len = 256;
                self.base_asym_enc = CStr::from_bytes_with_nul(b"pkcs1\0")?;
            }
            SPDM_ASYM_RSASSA_3072 => {
                self.sig_len = 384;
                self.base_asym_enc = CStr::from_bytes_with_nul(b"pkcs1\0")?;
            }
            SPDM_ASYM_RSASSA_4096 => {
                self.sig_len = 512;
                self.base_asym_enc = CStr::from_bytes_with_nul(b"pkcs1\0")?;
            }
            SPDM_ASYM_ECDSA_ECC_NIST_P256 => {
                self.sig_len = 64;
                self.base_asym_enc = CStr::from_bytes_with_nul(b"p1363\0")?;
            }
            SPDM_ASYM_ECDSA_ECC_NIST_P384 => {
                self.sig_len = 96;
                self.base_asym_enc = CStr::from_bytes_with_nul(b"p1363\0")?;
            }
            SPDM_ASYM_ECDSA_ECC_NIST_P521 => {
                self.sig_len = 132;
                self.base_asym_enc = CStr::from_bytes_with_nul(b"p1363\0")?;
            }
            _ => {
                pr_err!("Unknown asym algorithm\n");
                return Err(EINVAL);
            }
        }

        match self.base_hash_alg {
            SPDM_HASH_SHA_256 => {
                self.base_hash_alg_name = CStr::from_bytes_with_nul(b"sha256\0")?;
            }
            SPDM_HASH_SHA_384 => {
                self.base_hash_alg_name = CStr::from_bytes_with_nul(b"sha384\0")?;
            }
            SPDM_HASH_SHA_512 => {
                self.base_hash_alg_name = CStr::from_bytes_with_nul(b"sha512\0")?;
            }
            _ => {
                pr_err!("Unknown hash algorithm\n");
                return Err(EINVAL);
            }
        }

        // This is freed in when `SpdmState` is dropped, but this call
        // can happen multiple times.
        if self.shash != core::ptr::null_mut() {
            if let Some(desc) = self.desc.take() {
                // SAFETY: `self.shash` is a valid handle
                let desc_len = core::mem::size_of::<bindings::shash_desc>()
                    + unsafe { bindings::crypto_shash_descsize(self.shash) } as usize;

                // SAFETY: `desc` was allocated as a KVec<u8> with a length of `desc_len`
                // and then transmuted to a raw pointer with into_raw_parts()
                let desc_ptr =
                    unsafe { core::mem::transmute::<&mut bindings::shash_desc, *mut u8>(desc) };
                let desc_vec = unsafe { KVec::<u8>::from_raw_parts(desc_ptr, desc_len, desc_len) };
                drop(desc_vec);
            }

            unsafe {
                bindings::crypto_free_shash(self.shash);
            }
        }

        self.shash =
            unsafe { bindings::crypto_alloc_shash(self.base_hash_alg_name.as_char_ptr(), 0, 0) };
        if let Err(e) = from_err_ptr(self.shash) {
            self.shash = core::ptr::null_mut();
            return Err(e);
        }

        // SAFETY: `self.shash` is a valid handle (verified above).
        let desc_len = core::mem::size_of::<bindings::shash_desc>()
            + unsafe { bindings::crypto_shash_descsize(self.shash) } as usize;

        let desc_vec: KVec<u8> = KVec::from_elem(0u8, desc_len, GFP_KERNEL)?;
        // Consume the desc_vec to make sure it isn't dropped, untill we
        // manually drop it later
        let (desc_buf, _length, _capacity) = desc_vec.into_raw_parts();

        // SAFETY: We are casting the allocation to be a shash_desc
        let desc = unsafe {
            core::mem::transmute::<*mut c_void, &mut bindings::shash_desc>(desc_buf as *mut c_void)
        };
        desc.tfm = self.shash;

        self.desc = Some(desc);

        /* Used frequently to compute offsets, so cache H */
        self.hash_len = unsafe { bindings::crypto_shash_digestsize(self.shash) as usize };

        if let Some(desc) = &mut self.desc {
            // SAFETY: `self.desc` is a valid and initalised `shash_desc` sized buffer
            unsafe { to_result(bindings::crypto_shash_init(*desc)) }
        } else {
            Err(ENOMEM)
        }
    }

    pub(crate) fn negotiate_algs(&mut self) -> Result<(), Error> {
        let mut request = NegotiateAlgsReq::default();
        request.version = self.version;

        if self.version >= SPDM_VER_12 && (self.rsp_caps & SPDM_KEY_EX_CAP) == SPDM_KEY_EX_CAP {
            request.other_params_support = SPDM_OPAQUE_DATA_FMT_GENERAL;
        }

        let req_sz = core::mem::size_of::<NegotiateAlgsReq>();
        let rsp_sz = core::mem::size_of::<NegotiateAlgsRsp>();

        request.length = (req_sz as u16).to_le();

        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let request_buf = unsafe { from_raw_parts_mut(&mut request as *mut _ as *mut u8, req_sz) };

        let mut response_vec: KVec<u8> = KVec::from_elem(0u8, rsp_sz, GFP_KERNEL)?;

        let rc = self.spdm_exchange(request_buf, response_vec.as_mut_slice())? as usize;

        // The transport must report a length within the buffer we provided.
        if rc > response_vec.len() {
            pr_err!("Overflowed capabilities response\n");
            return Err(EIO);
        }
        response_vec.truncate(rc);

        let response: &NegotiateAlgsRsp = Untrusted::new(response_vec.as_slice()).validate()?;

        self.base_asym_alg = u32::from_le(response.base_asym_sel);
        self.base_hash_alg = u32::from_le(response.base_hash_sel);
        self.meas_hash_alg = u32::from_le(response.measurement_hash_algo);

        if self.base_asym_alg & SPDM_ASYM_ALGOS == 0 || self.base_hash_alg & SPDM_HASH_ALGOS == 0 {
            pr_err!("No common supported algorithms\n");
            return Err(EPROTO);
        }

        // /* Responder shall select exactly 1 alg (SPDM 1.0.0 table 14) */
        if self.base_asym_alg.count_ones() != 1
            || self.base_hash_alg.count_ones() != 1
            || self.meas_hash_alg.count_ones() != 1
            || response.ext_asym_sel_count != 0
            || response.ext_hash_sel_count != 0
            || response.param1 > request.param1
            || response.other_params_sel != request.other_params_support
        {
            pr_err!("Malformed algorithms response\n");
            return Err(EPROTO);
        }

        self.update_response_algs()?;

        Ok(())
    }

    pub(crate) fn get_digests(&mut self) -> Result<(), Error> {
        let mut request = GetDigestsReq::default();
        request.version = self.version;

        let req_sz = core::mem::size_of::<GetDigestsReq>();
        let rsp_sz = core::mem::size_of::<GetDigestsRsp>() + SPDM_SLOTS * self.hash_len;

        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let request_buf = unsafe { from_raw_parts_mut(&mut request as *mut _ as *mut u8, req_sz) };

        let mut response_vec: KVec<u8> = KVec::from_elem(0u8, rsp_sz, GFP_KERNEL)?;

        let len = self.spdm_exchange(request_buf, response_vec.as_mut_slice())? as usize;

        // The transport must report a length within the buffer we provided.
        if len > response_vec.len() {
            pr_err!("Overflowed digests response\n");
            return Err(EIO);
        }
        response_vec.truncate(len);

        let response: &GetDigestsRsp = Untrusted::new(response_vec.as_slice()).validate()?;

        if len
            < core::mem::size_of::<GetDigestsRsp>()
                + response.param2.count_ones() as usize * self.hash_len
        {
            pr_err!("Overflowed digests response\n");
            return Err(EIO);
        }

        let mut deprovisioned_slots = self.provisioned_slots & !response.param2;
        while (deprovisioned_slots.trailing_zeros() as usize) < SPDM_SLOTS {
            let slot = deprovisioned_slots.trailing_zeros() as usize;
            self.certs[slot].clear();
            deprovisioned_slots &= !(1 << slot);
        }

        if self.version >= SPDM_VER_13 && (response.param2 & !response.param1 != 0) {
            pr_err!("Malformed digests response\n");
            return Err(EPROTO);
        }

        self.provisioned_slots = response.param2;
        if self.provisioned_slots == 0 {
            pr_err!("No certificates provisioned\n");
            return Err(EPROTO);
        }

        let supported_slots = if self.version >= SPDM_VER_13 {
            response.param1
        } else {
            0xFF
        };

        self.supported_slots = supported_slots;

        Ok(())
    }
}
