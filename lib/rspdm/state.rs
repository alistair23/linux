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
    error::{code::EINVAL, from_err_ptr, to_result, Error},
    str::CStr,
    str::CString,
    validate::Untrusted,
};

use crate::consts::{
    SpdmErrorCode, SPDM_ASYM_ALGOS, SPDM_ASYM_ECDSA_ECC_NIST_P256, SPDM_ASYM_ECDSA_ECC_NIST_P384,
    SPDM_ASYM_ECDSA_ECC_NIST_P521, SPDM_ASYM_RSASSA_2048, SPDM_ASYM_RSASSA_3072,
    SPDM_ASYM_RSASSA_4096, SPDM_COMBINED_PREFIX_SZ, SPDM_ERROR, SPDM_GET_VERSION_LEN,
    SPDM_HASH_ALGOS, SPDM_HASH_SHA_256, SPDM_HASH_SHA_384, SPDM_HASH_SHA_512, SPDM_KEY_EX_CAP,
    SPDM_MAX_OPAQUE_DATA, SPDM_MAX_VER, SPDM_MEAS_CAP_MASK, SPDM_MEAS_SPEC_DMTF,
    SPDM_MIN_DATA_TRANSFER_SIZE, SPDM_MIN_VER, SPDM_OPAQUE_DATA_FMT_GENERAL, SPDM_PREFIX_SZ,
    SPDM_REQ, SPDM_RSP_MIN_CAPS, SPDM_SLOTS, SPDM_VER_10, SPDM_VER_11, SPDM_VER_12,
};
use crate::validator::{
    ChallengeReq, ChallengeRsp, GetCapabilitiesReq, GetCapabilitiesRsp, GetCertificateReq,
    GetCertificateRsp, GetDigestsReq, GetDigestsRsp, GetVersionReq, GetVersionRsp,
    NegotiateAlgsReq, NegotiateAlgsRsp, RegAlg, SpdmErrorRsp, SpdmHeader,
};

const SPDM_CONTEXT: &str = "responder-challenge_auth signing";

/// The current SPDM session state for a device. Based on the
/// C `struct spdm_state`.
///
/// `dev`: Responder device.  Used for error reporting and passed to @transport.
/// `transport`: Transport function to perform one message exchange.
/// `transport_priv`: Transport private data.
/// `transport_sz`: Maximum message size the transport is capable of (in bytes).
///  Used as DataTransferSize in GET_CAPABILITIES exchange.
/// `keyring`: Keyring against which to check the first certificate in
///  responder's certificate chain.
/// `validate`: Function to validate additional leaf certificate requirements.
///
/// `version`: Maximum common supported version of requester and responder.
///  Negotiated during GET_VERSION exchange.
/// @rsp_caps: Cached capabilities of responder.
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
/// @base_hash_alg_name: Human-readable name of @base_hash_alg.
///  Passed to crypto subsystem when calling crypto_alloc_shash() and
///  verify_signature().
/// @shash: Synchronous hash handle for @base_hash_alg computation.
/// @desc: Synchronous hash context for @base_hash_alg computation.
/// @hash_len: Hash length of @base_hash_alg (in bytes).
///  H in SPDM specification.
/// @slot: Certificate chain in each of the 8 slots.  NULL pointer if a slot is
///  not populated.  Prefixed by the 4 + H header per SPDM 1.0.0 table 15.
/// @slot_sz: Certificate chain size (in bytes).
/// @leaf_key: Public key portion of leaf certificate against which to check
///  responder's signatures.
/// @transcript: Concatenation of all SPDM messages exchanged during an
///  authentication or measurement sequence.  Used to verify the signature,
///  as it is computed over the hashed transcript.
/// @next_nonce: Requester nonce to be used for the next authentication
///  sequence.  Populated from user space through sysfs.
///  If user space does not provide a nonce, the kernel uses a random one.
///
/// `authenticated`: Whether device was authenticated successfully.
pub struct SpdmState {
    pub(crate) dev: *mut bindings::device,
    pub(crate) transport: bindings::spdm_transport,
    pub(crate) transport_priv: *mut c_void,
    pub(crate) transport_sz: u32,
    pub(crate) keyring: *mut bindings::key,
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
    base_asym_enc: &'static CStr,
    sig_len: usize,

    /* Hash algorithm */
    base_hash_alg_name: &'static CStr,
    pub(crate) shash: *mut bindings::crypto_shash,
    pub(crate) desc: Option<&'static mut bindings::shash_desc>,
    pub(crate) hash_len: usize,

    pub(crate) authenticated: bool,

    // Certificates
    pub(crate) slot: [Option<KVec<u8>>; SPDM_SLOTS],
    slot_sz: [usize; SPDM_SLOTS],
    pub(crate) leaf_key: Option<*mut bindings::public_key>,

    transcript: KVec<u8>,

    next_nonce: Option<&'static mut [u8]>,
}

#[repr(C, packed)]
pub(crate) struct SpdmCertChain {
    length: u16,
    _reserved: [u8; 2],
    root_hash: bindings::__IncompleteArrayField<u8>,
    certificates: bindings::__IncompleteArrayField<u8>,
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
            authenticated: false,
            slot: [const { None }; SPDM_SLOTS],
            slot_sz: [0; SPDM_SLOTS],
            leaf_key: None,
            transcript: KVec::new(),
            next_nonce: None,
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
        }
    }

    /// Start a SPDM exchange
    ///
    /// The data in `request_buf` is sent to the device and the response is
    /// stored in `response_buf`.
    pub(crate) fn spdm_exchange(
        &mut self,
        request_buf: &mut [u8],
        response_buf: &mut [u8],
    ) -> Result<i32, Error> {
        let header_size = core::mem::size_of::<SpdmHeader>();
        let request: &mut SpdmHeader = Untrusted::new_mut(request_buf).validate_mut()?;
        let response: &SpdmHeader = Untrusted::new_ref(response_buf).validate()?;

        self.transcript.extend_from_slice(request_buf, GFP_KERNEL)?;

        let transport_function = self.transport.ok_or(EINVAL)?;
        // SAFETY: `transport_function` is provided by the new(), we are
        // calling the function.
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
        if response.code == SPDM_ERROR {
            if length as usize >= core::mem::size_of::<SpdmErrorRsp>() {
                // SAFETY: The response buffer will be at at least as large as
                // `SpdmErrorRsp` so we can cast the buffer to `SpdmErrorRsp` which
                // is a packed struct.
                self.spdm_err(unsafe { &*(response_buf.as_ptr() as *const SpdmErrorRsp) })?;
            } else {
                return Err(EINVAL);
            }
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
        let mut request = GetVersionReq::default();
        request.version = self.version;

        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let request_buf = unsafe {
            from_raw_parts_mut(
                &mut request as *mut _ as *mut u8,
                core::mem::size_of::<GetVersionReq>(),
            )
        };

        let mut response_vec: KVec<u8> = KVec::with_capacity(SPDM_GET_VERSION_LEN, GFP_KERNEL)?;
        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let response_buf =
            unsafe { from_raw_parts_mut(response_vec.as_mut_ptr(), SPDM_GET_VERSION_LEN) };

        let rc = self.spdm_exchange(request_buf, response_buf)?;

        // SAFETY: `rc` is the length of data read, which will be smaller
        // then the capacity of the vector
        unsafe { response_vec.inc_len(rc as usize) };

        let response: &mut GetVersionRsp = Untrusted::new_mut(&mut response_vec).validate_mut()?;
        let rsp_sz = core::mem::size_of::<SpdmHeader>()
            + 2
            + response.version_number_entry_count as usize * 2;

        self.transcript
            .extend_from_slice(&response_vec[..rsp_sz], GFP_KERNEL)?;

        let mut foundver = false;
        for i in 0..response.version_number_entry_count {
            // Creating a reference on a packed struct will result in
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

    /// Obtain the supported capabilities from an SPDM session and store the
    /// information in the `SpdmState`.
    pub(crate) fn get_capabilities(&mut self) -> Result<(), Error> {
        let mut request = GetCapabilitiesReq::default();
        request.version = self.version;

        let (req_sz, rsp_sz) = match self.version {
            SPDM_VER_10 => (4, 8),
            SPDM_VER_11 => (8, 8),
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

        let mut response_vec: KVec<u8> = KVec::with_capacity(rsp_sz, GFP_KERNEL)?;
        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let response_buf = unsafe { from_raw_parts_mut(response_vec.as_mut_ptr(), rsp_sz) };

        let rc = self.spdm_exchange(request_buf, response_buf)?;

        if rc < (rsp_sz as i32) {
            pr_err!("Truncated capabilities response\n");
            to_result(-(bindings::EIO as i32))?;
        }

        // SAFETY: `rc` is the length of data read, which will be smaller
        // then the capacity of the vector
        unsafe { response_vec.inc_len(rc as usize) };

        let response: &mut GetCapabilitiesRsp =
            Untrusted::new_mut(&mut response_vec).validate_mut()?;

        self.transcript
            .extend_from_slice(&response_vec[..rsp_sz], GFP_KERNEL)?;

        self.rsp_caps = u32::from_le(response.flags);
        if (self.rsp_caps & SPDM_RSP_MIN_CAPS) != SPDM_RSP_MIN_CAPS {
            to_result(-(bindings::EPROTONOSUPPORT as i32))?;
        }

        if self.version >= SPDM_VER_12 {
            if response.data_transfer_size < SPDM_MIN_DATA_TRANSFER_SIZE {
                pr_err!("Malformed capabilities response\n");
                to_result(-(bindings::EPROTO as i32))?;
            }
            self.transport_sz = self.transport_sz.min(response.data_transfer_size);
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

        /*
         * shash and desc allocations are reused for subsequent measurement
         * retrieval, hence are not freed until spdm_reset().
         */
        self.shash =
            unsafe { bindings::crypto_alloc_shash(self.base_hash_alg_name.as_char_ptr(), 0, 0) };
        if self.shash.is_null() {
            return Err(ENOMEM);
        }

        let desc_len = core::mem::size_of::<bindings::shash_desc>()
            + unsafe { bindings::crypto_shash_descsize(self.shash) } as usize;

        let mut desc_vec: KVec<u8> = KVec::with_capacity(desc_len, GFP_KERNEL)?;
        // SAFETY: `desc_vec` is `desc_len` long
        let desc_buf = unsafe { from_raw_parts_mut(desc_vec.as_mut_ptr(), desc_len) };

        let desc = unsafe {
            core::mem::transmute::<*mut c_void, &mut bindings::shash_desc>(
                desc_buf.as_mut_ptr() as *mut c_void
            )
        };
        desc.tfm = self.shash;

        self.desc = Some(desc);

        /* Used frequently to compute offsets, so cache H */
        self.hash_len = unsafe { bindings::crypto_shash_digestsize(self.shash) as usize };

        if let Some(desc) = &mut self.desc {
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

        // TODO support more algs
        let reg_alg_entries = 0;

        let req_sz = core::mem::size_of::<NegotiateAlgsReq>()
            + core::mem::size_of::<RegAlg>() * reg_alg_entries;
        let rsp_sz = core::mem::size_of::<NegotiateAlgsRsp>()
            + core::mem::size_of::<RegAlg>() * reg_alg_entries;

        request.length = req_sz as u16;
        request.param1 = reg_alg_entries as u8;

        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let request_buf = unsafe { from_raw_parts_mut(&mut request as *mut _ as *mut u8, req_sz) };

        let mut response_vec: KVec<u8> = KVec::with_capacity(rsp_sz, GFP_KERNEL)?;
        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let response_buf = unsafe { from_raw_parts_mut(response_vec.as_mut_ptr(), rsp_sz) };

        let rc = self.spdm_exchange(request_buf, response_buf)?;

        if rc < (rsp_sz as i32) {
            pr_err!("Truncated capabilities response\n");
            to_result(-(bindings::EIO as i32))?;
        }

        // SAFETY: `rc` is the length of data read, which will be smaller
        // then the capacity of the vector
        unsafe { response_vec.inc_len(rc as usize) };

        let response: &mut NegotiateAlgsRsp =
            Untrusted::new_mut(&mut response_vec).validate_mut()?;

        self.transcript
            .extend_from_slice(&response_vec[..rsp_sz], GFP_KERNEL)?;

        self.base_asym_alg = response.base_asym_sel;
        self.base_hash_alg = response.base_hash_sel;
        self.meas_hash_alg = response.measurement_hash_algo;

        if self.base_asym_alg & SPDM_ASYM_ALGOS == 0 || self.base_hash_alg & SPDM_HASH_ALGOS == 0 {
            pr_err!("No common supported algorithms\n");
            to_result(-(bindings::EPROTO as i32))?;
        }

        // /* Responder shall select exactly 1 alg (SPDM 1.0.0 table 14) */
        if self.base_asym_alg.count_ones() != 1
            || self.base_hash_alg.count_ones() != 1
            || response.ext_asym_sel_count != 0
            || response.ext_hash_sel_count != 0
            || response.param1 > request.param1
            || response.other_params_sel != request.other_params_support
        {
            pr_err!("Malformed algorithms response\n");
            to_result(-(bindings::EPROTO as i32))?;
        }

        if self.rsp_caps & SPDM_MEAS_CAP_MASK == SPDM_MEAS_CAP_MASK
            && (self.meas_hash_alg.count_ones() != 1
                || response.measurement_specification_sel != SPDM_MEAS_SPEC_DMTF)
        {
            pr_err!("Malformed algorithms response\n");
            to_result(-(bindings::EPROTO as i32))?;
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

        let mut response_vec: KVec<u8> = KVec::with_capacity(rsp_sz, GFP_KERNEL)?;
        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let response_buf = unsafe { from_raw_parts_mut(response_vec.as_mut_ptr(), rsp_sz) };

        let rc = self.spdm_exchange(request_buf, response_buf)?;

        if rc < (core::mem::size_of::<GetDigestsRsp>() as i32) {
            pr_err!("Truncated digests response\n");
            to_result(-(bindings::EIO as i32))?;
        }

        // SAFETY: `rc` is the length of data read, which will be smaller
        // then the capacity of the vector
        unsafe { response_vec.inc_len(rc as usize) };

        let response: &mut GetDigestsRsp = Untrusted::new_mut(&mut response_vec).validate_mut()?;
        let rsp_sz = core::mem::size_of::<SpdmHeader>() + response.param2 as usize * self.hash_len;

        self.transcript
            .extend_from_slice(&response_vec[..rsp_sz], GFP_KERNEL)?;

        if rc
            < (core::mem::size_of::<GetDigestsReq>()
                + response.param2.count_ones() as usize * self.hash_len) as i32
        {
            pr_err!("Truncated digests response\n");
            to_result(-(bindings::EIO as i32))?;
        }

        let mut deprovisioned_slots = self.provisioned_slots & !response.param2;
        while (deprovisioned_slots.trailing_zeros() as usize) < SPDM_SLOTS {
            let slot = deprovisioned_slots.trailing_zeros() as usize;
            self.slot[slot] = None;
            self.slot_sz[slot] = 0;
            deprovisioned_slots &= !(1 << slot);
        }

        self.provisioned_slots = response.param2;
        if self.provisioned_slots == 0 {
            pr_err!("No certificates provisioned\n");
            to_result(-(bindings::EPROTO as i32))?;
        }

        if self.version >= 0x13 && (response.param2 & !response.param1 != 0) {
            pr_err!("Malformed digests response\n");
            to_result(-(bindings::EPROTO as i32))?;
        }

        let supported_slots = if self.version >= 0x13 {
            response.param1
        } else {
            0xFF
        };

        if self.supported_slots != supported_slots {
            self.supported_slots = supported_slots;
        }

        Ok(())
    }

    fn get_cert_exchange(
        &mut self,
        request_buf: &mut [u8],
        response_vec: &mut KVec<u8>,
        rsp_sz: usize,
    ) -> Result<&mut GetCertificateRsp, Error> {
        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let response_buf = unsafe { from_raw_parts_mut(response_vec.as_mut_ptr(), rsp_sz) };

        let rc = self.spdm_exchange(request_buf, response_buf)?;

        if rc < (core::mem::size_of::<GetCertificateReq>() as i32) {
            pr_err!("Truncated certificate response\n");
            to_result(-(bindings::EIO as i32))?;
        }

        // SAFETY: `rc` is the length of data read, which will be smaller
        // then the capacity of the vector
        unsafe { response_vec.inc_len(rc as usize) };

        let response: &mut GetCertificateRsp = Untrusted::new_mut(response_vec).validate_mut()?;
        let rsp_sz = core::mem::size_of::<SpdmHeader>() + 4 + response.portion_length as usize;

        self.transcript
            .extend_from_slice(&response_vec[..rsp_sz], GFP_KERNEL)?;

        if rc
            < (core::mem::size_of::<GetCertificateRsp>() + response.portion_length as usize) as i32
        {
            pr_err!("Truncated certificate response\n");
            to_result(-(bindings::EIO as i32))?;
        }

        Ok(response)
    }

    pub(crate) fn get_certificate(&mut self, slot: u8) -> Result<(), Error> {
        let mut request = GetCertificateReq::default();
        request.version = self.version;
        request.param1 = slot;

        let req_sz = core::mem::size_of::<GetCertificateReq>();
        let rsp_sz = ((core::mem::size_of::<GetCertificateRsp>() + 0xffff) as u32)
            .min(self.transport_sz) as usize;

        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let request_buf = unsafe { from_raw_parts_mut(&mut request as *mut _ as *mut u8, req_sz) };

        let mut response_vec: KVec<u8> = KVec::with_capacity(rsp_sz, GFP_KERNEL)?;

        request.offset = 0;
        request.length = (rsp_sz - core::mem::size_of::<GetCertificateRsp>()).to_le() as u16;

        let response = self.get_cert_exchange(request_buf, &mut response_vec, rsp_sz)?;

        let total_cert_len =
            ((response.portion_length + response.remainder_length) & 0xFFFF) as usize;

        let mut certs_buf: KVec<u8> = KVec::new();

        certs_buf.extend_from_slice(
            &response_vec[8..(8 + response.portion_length as usize)],
            GFP_KERNEL,
        )?;

        let mut offset: usize = response.portion_length as usize;
        let mut remainder_length = response.remainder_length as usize;

        while remainder_length > 0 {
            request.offset = offset.to_le() as u16;
            request.length = (remainder_length
                .min(rsp_sz - core::mem::size_of::<GetCertificateRsp>()))
            .to_le() as u16;

            let response = self.get_cert_exchange(request_buf, &mut response_vec, rsp_sz)?;

            if response.portion_length == 0
                || (response.param1 & 0xF) != slot
                || offset as u16 + response.portion_length + response.remainder_length
                    != total_cert_len as u16
            {
                pr_err!("Malformed certificate response\n");
                to_result(-(bindings::EPROTO as i32))?;
            }

            certs_buf.extend_from_slice(
                &response_vec[8..(8 + response.portion_length as usize)],
                GFP_KERNEL,
            )?;
            offset += response.portion_length as usize;
            remainder_length = response.remainder_length as usize;
        }

        let header_length = core::mem::size_of::<SpdmCertChain>() + self.hash_len;

        let ptr = certs_buf.as_mut_ptr();
        // SAFETY: `SpdmCertChain` is repr(C) and packed, so we can convert it from a slice
        let ptr = ptr.cast::<SpdmCertChain>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        let certs: &mut SpdmCertChain = unsafe { &mut *ptr };

        if total_cert_len < header_length
            || total_cert_len != usize::from_le(certs.length as usize)
            || total_cert_len != certs_buf.len()
        {
            pr_err!("Malformed certificate chain in slot {slot}\n");
            to_result(-(bindings::EPROTO as i32))?;
        }

        self.slot_sz[slot as usize] = total_cert_len;
        self.slot[slot as usize] = Some(certs_buf);

        Ok(())
    }

    pub(crate) fn validate_cert_chain(&mut self, slot: u8) -> Result<(), Error> {
        let cert_chain_buf = self.slot[slot as usize].as_ref().ok_or(ENOMEM)?;
        let cert_chain_len = self.slot_sz[slot as usize];
        let header_len = 4 + self.hash_len;

        let mut offset = header_len;
        let mut prev_cert: Option<*mut bindings::x509_certificate> = None;

        while offset < cert_chain_len {
            let cert_len = unsafe {
                bindings::x509_get_certificate_length(
                    &cert_chain_buf[offset..] as *const _ as *const u8,
                    cert_chain_len - offset,
                )
            };

            if cert_len < 0 {
                pr_err!("Invalid certificate length\n");
                to_result(cert_len as i32)?;
            }

            let _is_leaf_cert = if offset + cert_len as usize == cert_chain_len {
                true
            } else {
                false
            };

            let cert_ptr = unsafe {
                from_err_ptr(bindings::x509_cert_parse(
                    &cert_chain_buf[offset..] as *const _ as *const c_void,
                    cert_len as usize,
                ))?
            };
            let cert = unsafe { *cert_ptr };

            if cert.unsupported_sig || cert.blacklisted {
                to_result(-(bindings::EKEYREJECTED as i32))?;
            }

            if let Some(prev) = prev_cert {
                // Check against previous certificate
                let rc = unsafe { bindings::public_key_verify_signature((*prev).pub_, cert.sig) };

                if rc < 0 {
                    pr_err!("Signature validation error\n");
                    to_result(rc)?;
                }
            } else {
                // Check aginst root keyring
                let key = unsafe {
                    from_err_ptr(bindings::find_asymmetric_key(
                        self.keyring,
                        (*cert.sig).auth_ids[0],
                        (*cert.sig).auth_ids[1],
                        (*cert.sig).auth_ids[2],
                        false,
                    ))?
                };

                let rc = unsafe { bindings::verify_signature(key, cert.sig) };
                unsafe { bindings::key_put(key) };

                if rc < 0 {
                    pr_err!("Root signature validation error\n");
                    to_result(rc)?;
                }
            }

            if let Some(prev) = prev_cert {
                unsafe { bindings::x509_free_certificate(prev) };
            }

            prev_cert = Some(cert_ptr);
            offset += cert_len as usize;
        }

        if let Some(prev) = prev_cert {
            if let Some(validate) = self.validate {
                let rc = unsafe { validate(self.dev, slot, prev) };
                to_result(rc)?;
            }

            self.leaf_key = unsafe { Some((*prev).pub_) };
        }

        Ok(())
    }

    pub(crate) fn challenge_rsp_len(&mut self, nonce_len: usize, opaque_len: usize) -> usize {
        let mut length =
            core::mem::size_of::<SpdmHeader>() + self.hash_len + nonce_len + opaque_len + 2;

        if self.version >= 0x13 {
            length += 8;
        }

        length + self.sig_len
    }

    fn verify_signature(&mut self, response_vec: &mut [u8]) -> Result<(), Error> {
        let sig_start = response_vec.len() - self.sig_len;
        let mut sig = bindings::public_key_signature::default();
        let mut mhash: KVec<u8> = KVec::new();

        sig.s = &mut response_vec[sig_start..] as *mut _ as *mut u8;
        sig.s_size = self.sig_len as u32;
        sig.encoding = self.base_asym_enc.as_ptr() as *const u8;
        sig.hash_algo = self.base_hash_alg_name.as_ptr() as *const u8;

        let mut m: KVec<u8> = KVec::new();
        m.extend_with(SPDM_COMBINED_PREFIX_SZ + self.hash_len, 0, GFP_KERNEL)?;

        if let Some(desc) = &mut self.desc {
            desc.tfm = self.shash;

            unsafe {
                to_result(bindings::crypto_shash_digest(
                    *desc,
                    self.transcript.as_ptr(),
                    (self.transcript.len() - self.sig_len) as u32,
                    m[SPDM_COMBINED_PREFIX_SZ..].as_mut_ptr(),
                ))?;
            };
        } else {
            to_result(-(bindings::EPROTO as i32))?;
        }

        if self.version <= 0x11 {
            sig.digest = m[SPDM_COMBINED_PREFIX_SZ..].as_mut_ptr();
        } else {
            let major = self.version >> 4;
            let minor = self.version & 0xF;

            let output = CString::try_from_fmt(fmt!("dmtf-spdm-v{major:x}.{minor:x}.*dmtf-spdm-v{major:x}.{minor:x}.*dmtf-spdm-v{major:x}.{minor:x}.*dmtf-spdm-v{major:x}.{minor:x}.*"))?;
            let mut buf = output.into_vec();
            let zero_pad_len = SPDM_COMBINED_PREFIX_SZ - SPDM_PREFIX_SZ - SPDM_CONTEXT.len() - 1;

            buf.extend_with(zero_pad_len, 0, GFP_KERNEL)?;
            buf.extend_from_slice(SPDM_CONTEXT.as_bytes(), GFP_KERNEL)?;

            m[..SPDM_COMBINED_PREFIX_SZ].copy_from_slice(&buf);

            mhash.extend_with(self.hash_len, 0, GFP_KERNEL)?;

            if let Some(desc) = &mut self.desc {
                desc.tfm = self.shash;

                unsafe {
                    to_result(bindings::crypto_shash_digest(
                        *desc,
                        m.as_ptr(),
                        m.len() as u32,
                        mhash.as_mut_ptr(),
                    ))?;
                };
            } else {
                to_result(-(bindings::EPROTO as i32))?;
            }

            sig.digest = mhash.as_mut_ptr();
        }

        sig.digest_size = self.hash_len as u32;

        if let Some(leaf_key) = self.leaf_key {
            unsafe { to_result(bindings::public_key_verify_signature(leaf_key, &sig)) }
        } else {
            to_result(-(bindings::EPROTO as i32))
        }
    }

    pub(crate) fn challenge(&mut self, slot: u8, verify: bool) -> Result<(), Error> {
        let mut request = ChallengeReq::default();
        request.version = self.version;
        request.param1 = slot;

        let nonce_len = request.nonce.len();

        if let Some(nonce) = &self.next_nonce {
            request.nonce.copy_from_slice(&nonce);
            self.next_nonce = None;
        } else {
            unsafe {
                bindings::get_random_bytes(&mut request.nonce as *mut _ as *mut c_void, nonce_len)
            };
        }

        let req_sz = if self.version <= 0x12 {
            core::mem::size_of::<ChallengeReq>() - 8
        } else {
            core::mem::size_of::<ChallengeReq>()
        };

        let rsp_sz = self.challenge_rsp_len(nonce_len, SPDM_MAX_OPAQUE_DATA);

        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let request_buf = unsafe { from_raw_parts_mut(&mut request as *mut _ as *mut u8, req_sz) };

        let mut response_vec: KVec<u8> = KVec::with_capacity(rsp_sz, GFP_KERNEL)?;
        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let response_buf = unsafe { from_raw_parts_mut(response_vec.as_mut_ptr(), rsp_sz) };

        let rc = self.spdm_exchange(request_buf, response_buf)?;

        if rc < (core::mem::size_of::<ChallengeRsp>() as i32) {
            pr_err!("Truncated challenge response\n");
            to_result(-(bindings::EIO as i32))?;
        }

        // SAFETY: `rc` is the length of data read, which will be smaller
        // then the capacity of the vector
        unsafe { response_vec.inc_len(rc as usize) };

        let _response: &mut ChallengeRsp = Untrusted::new_mut(&mut response_vec).validate_mut()?;

        let opaque_len_offset = core::mem::size_of::<SpdmHeader>() + self.hash_len + nonce_len;
        let opaque_len = u16::from_le_bytes(
            response_vec[opaque_len_offset..(opaque_len_offset + 2)]
                .try_into()
                .unwrap_or([0, 0]),
        );

        let rsp_sz = self.challenge_rsp_len(nonce_len, opaque_len as usize);

        if rc < rsp_sz as i32 {
            pr_err!("Truncated challenge response\n");
            to_result(-(bindings::EIO as i32))?;
        }

        self.transcript
            .extend_from_slice(&response_vec[..rsp_sz], GFP_KERNEL)?;

        if verify {
            /* Verify signature at end of transcript against leaf key */
            match self.verify_signature(&mut response_vec[..rsp_sz]) {
                Ok(()) => {
                    pr_info!("Authenticated with certificate slot {slot}");
                    self.authenticated = true;
                }
                Err(e) => {
                    pr_err!("Cannot verify challenge_auth signature: {e:?}");
                    self.authenticated = false;
                }
            };
        }

        Ok(())
    }
}
