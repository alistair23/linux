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
    SPDM_MEAS_RESP_CAP,
    SPDM_MIN_VER,
    SPDM_OPAQUE_DATA_FMT_GENERAL,
    SPDM_REQ,
    SPDM_RSP_MIN_CAPS,
    SPDM_VER_10,
    SPDM_VER_11,
    SPDM_VER_12, //
};
use crate::validator::{
    GetCapabilitiesReq,
    GetCapabilitiesRsp,
    GetVersionReq,
    GetVersionRsp,
    NegotiateAlgsReq,
    NegotiateAlgsRsp,
    SpdmErrorRsp,
    SpdmHeader,
    GET_CAPABILITIES_RSP_SZ,
    NEGOTIATE_ALGS_RSP_SZ, //
};

/// The current SPDM session state for a device.
///
/// Concurrent access is serialised by wrapping the whole struct in a
/// `Mutex<SpdmState>` at the FFI boundary, so `spdm_authenticate()` callers
/// run one at a time and the locked `&mut SpdmState` is the only way to
/// reach the inner fields.
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

    /* Signature algorithm */
    base_asym_enc: &'a CStr,
    sig_len: usize,

    /* Hash algorithm */
    base_hash_alg_name: &'a CStr,
    pub(crate) shash: *mut bindings::crypto_shash,
    pub(crate) desc: *mut bindings::shash_desc,
    pub(crate) hash_len: usize,
}

impl Drop for SpdmState<'_> {
    fn drop(&mut self) {
        self.free_desc();

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
            base_asym_enc: unsafe { CStr::from_bytes_with_nul_unchecked(b"\0") },
            sig_len: 0,
            base_hash_alg_name: unsafe { CStr::from_bytes_with_nul_unchecked(b"\0") },
            shash: core::ptr::null_mut(),
            desc: core::ptr::null_mut(),
            hash_len: 0,
        }
    }

    /// Free the `shash_desc` buffer if one is allocated.
    fn free_desc(&mut self) {
        if !self.desc.is_null() {
            // SAFETY: `self.shash` is a valid handle when `desc` is allocated.
            let desc_len = core::mem::size_of::<bindings::shash_desc>()
                + unsafe { bindings::crypto_shash_descsize(self.shash) } as usize;

            // SAFETY: `desc` points to a KVec<u8> allocation of `desc_len`
            // bytes handed out with `KVec::into_raw_parts()`.
            let desc_vec =
                unsafe { KVec::<u8>::from_raw_parts(self.desc as *mut u8, desc_len, desc_len) };
            drop(desc_vec);
            self.desc = core::ptr::null_mut();
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
        let request: SpdmHeader = Untrusted::new(&request_buf[..]).validate(&*self)?;

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

        let response: SpdmHeader = Untrusted::new(&response_buf[..]).validate(&*self)?;

        if response.code == SPDM_ERROR {
            let error_rsp: SpdmErrorRsp =
                Untrusted::new(&response_buf[..header_size as usize]).validate(&*self)?;
            self.spdm_err(&error_rsp)?;
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
        request.header.version = SPDM_MIN_VER;
        self.version = SPDM_MIN_VER;

        let mut request_buf = request.to_bytes()?;

        let mut response_vec: KVec<u8> = KVec::from_elem(0u8, SPDM_GET_VERSION_LEN, GFP_KERNEL)?;

        let rc =
            self.spdm_exchange(request_buf.as_mut_slice(), response_vec.as_mut_slice())? as usize;

        // The transport must report a length within the buffer we provided.
        if rc > response_vec.len() {
            return Err(EINVAL);
        }
        response_vec.truncate(rc);

        let response: GetVersionRsp = Untrusted::new(response_vec.as_slice()).validate(&*self)?;

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

    /// Obtain the supported capabilities from an SPDM session and store the
    /// information in the `SpdmState`.
    pub(crate) fn get_capabilities(&mut self) -> Result<(), Error> {
        let mut request = GetCapabilitiesReq::default();
        request.header.version = self.version;

        let rsp_sz = match self.version {
            SPDM_VER_10 | SPDM_VER_11 => {
                core::mem::size_of::<SpdmHeader>() + 4 + core::mem::size_of::<u32>()
            }
            _ => {
                request.data_transfer_size = self.transport_sz;
                request.max_spdm_msg_size = self.transport_sz;

                (GET_CAPABILITIES_RSP_SZ as u32 + u16::MAX as u32).min(self.transport_sz) as usize
            }
        };

        let mut request_buf = request.to_bytes()?;

        let mut response_vec: KVec<u8> = KVec::from_elem(0u8, rsp_sz, GFP_KERNEL)?;

        let rc =
            self.spdm_exchange(request_buf.as_mut_slice(), response_vec.as_mut_slice())? as usize;
        response_vec.truncate(rc);

        let response: GetCapabilitiesRsp =
            Untrusted::new(response_vec.as_slice()).validate(&*self)?;

        self.rsp_caps = response.flags;
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
            if response.data_transfer_size < 42 {
                pr_err!(
                    "Invalid minimum transport size {}, must be at least 42\n",
                    response.data_transfer_size
                );
                return Err(EPROTONOSUPPORT);
            }

            self.transport_sz = self.transport_sz.min(response.data_transfer_size);
        }

        Ok(())
    }

    fn update_response_algs(&mut self) -> Result<(), Error> {
        match self.base_asym_alg {
            #[cfg(CONFIG_CRYPTO_RSA)]
            SPDM_ASYM_RSASSA_2048 => {
                self.sig_len = 256;
                self.base_asym_enc = CStr::from_bytes_with_nul(b"pkcs1\0")?;
            }
            #[cfg(CONFIG_CRYPTO_RSA)]
            SPDM_ASYM_RSASSA_3072 => {
                self.sig_len = 384;
                self.base_asym_enc = CStr::from_bytes_with_nul(b"pkcs1\0")?;
            }
            #[cfg(CONFIG_CRYPTO_RSA)]
            SPDM_ASYM_RSASSA_4096 => {
                self.sig_len = 512;
                self.base_asym_enc = CStr::from_bytes_with_nul(b"pkcs1\0")?;
            }
            #[cfg(CONFIG_CRYPTO_ECDSA)]
            SPDM_ASYM_ECDSA_ECC_NIST_P256 => {
                self.sig_len = 64;
                self.base_asym_enc = CStr::from_bytes_with_nul(b"p1363\0")?;
            }
            #[cfg(CONFIG_CRYPTO_ECDSA)]
            SPDM_ASYM_ECDSA_ECC_NIST_P384 => {
                self.sig_len = 96;
                self.base_asym_enc = CStr::from_bytes_with_nul(b"p1363\0")?;
            }
            #[cfg(CONFIG_CRYPTO_ECDSA)]
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
            #[cfg(CONFIG_CRYPTO_SHA256)]
            SPDM_HASH_SHA_256 => {
                self.base_hash_alg_name = CStr::from_bytes_with_nul(b"sha256\0")?;
            }
            #[cfg(CONFIG_CRYPTO_SHA512)]
            SPDM_HASH_SHA_384 => {
                self.base_hash_alg_name = CStr::from_bytes_with_nul(b"sha384\0")?;
            }
            #[cfg(CONFIG_CRYPTO_SHA512)]
            SPDM_HASH_SHA_512 => {
                self.base_hash_alg_name = CStr::from_bytes_with_nul(b"sha512\0")?;
            }
            _ => {
                pr_err!("Unknown hash algorithm\n");
                return Err(EINVAL);
            }
        }

        // This is freed when `SpdmState` is dropped, but this call
        // can happen multiple times.
        if self.shash != core::ptr::null_mut() {
            self.free_desc();

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

        let desc = desc_buf as *mut bindings::shash_desc;

        // SAFETY: `desc` points to an allocation of `desc_len` bytes, which is
        // large enough for a `shash_desc` header and its trailing context.
        unsafe { (*desc).tfm = self.shash };

        self.desc = desc;

        // Used frequently to compute offsets, so cache H
        self.hash_len = unsafe { bindings::crypto_shash_digestsize(self.shash) as usize };

        // SAFETY: `self.desc` points to a valid `shash_desc` sized buffer
        // with `tfm` initialised above.
        unsafe { to_result(bindings::crypto_shash_init(desc)) }
    }

    pub(crate) fn negotiate_algs(&mut self) -> Result<(), Error> {
        let mut request = NegotiateAlgsReq::default();
        request.header.version = self.version;

        if self.version >= SPDM_VER_12 && (self.rsp_caps & SPDM_KEY_EX_CAP) == SPDM_KEY_EX_CAP {
            request.other_params_support = SPDM_OPAQUE_DATA_FMT_GENERAL;
        }

        let rsp_sz =
            (NEGOTIATE_ALGS_RSP_SZ as u32 + u16::MAX as u32).min(self.transport_sz) as usize;

        request.length = NegotiateAlgsReq::WIRE_SIZE as u16;

        let mut request_buf = request.to_bytes()?;

        let mut response_vec: KVec<u8> = KVec::from_elem(0u8, rsp_sz, GFP_KERNEL)?;

        let rc =
            self.spdm_exchange(request_buf.as_mut_slice(), response_vec.as_mut_slice())? as usize;
        response_vec.truncate(rc);

        let response: NegotiateAlgsRsp =
            Untrusted::new(response_vec.as_slice()).validate(&*self)?;

        self.base_asym_alg = response.base_asym_sel;
        self.base_hash_alg = response.base_hash_sel;
        self.meas_hash_alg = response.measurement_hash_algo;

        if self.base_asym_alg & SPDM_ASYM_ALGOS == 0 || self.base_hash_alg & SPDM_HASH_ALGOS == 0 {
            pr_err!("No common supported algorithms\n");
            return Err(EPROTO);
        }

        let meas_hash_valid = if self.rsp_caps & SPDM_MEAS_RESP_CAP != 0
            && response.measurement_specification_sel != 0
        {
            self.meas_hash_alg.count_ones() == 1
        } else {
            self.meas_hash_alg == 0
        };

        // /* Responder shall select exactly 1 alg (SPDM 1.0.0 table 14) */
        if self.base_asym_alg.count_ones() != 1
            || self.base_hash_alg.count_ones() != 1
            || !meas_hash_valid
            || response.ext_asym_sel_count != 0
            || response.ext_hash_sel_count != 0
            || response.header.param1 > request.header.param1
            || response.other_params_sel != request.other_params_support
        {
            pr_err!("Malformed algorithms response\n");
            return Err(EPROTO);
        }

        self.update_response_algs()?;

        Ok(())
    }
}
