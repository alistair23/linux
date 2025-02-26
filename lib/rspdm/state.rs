// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Western Digital

//! The `SpdmState` struct and implementation.
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use core::ffi::c_void;
use core::mem::offset_of;
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
    str::CString,
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
    SPDM_COMBINED_PREFIX_SZ,
    SPDM_ERROR,
    SPDM_GET_VERSION_LEN,
    SPDM_HASH_ALGOS,
    SPDM_HASH_SHA_256,
    SPDM_HASH_SHA_384,
    SPDM_HASH_SHA_512,
    SPDM_KEY_EX_CAP,
    SPDM_MAX_OPAQUE_DATA,
    SPDM_MAX_VER,
    SPDM_MIN_DATA_TRANSFER_SIZE,
    SPDM_MIN_VER,
    SPDM_OPAQUE_DATA_FMT_GENERAL,
    SPDM_PREFIX_SZ,
    SPDM_REQ,
    SPDM_RSP_MIN_CAPS,
    SPDM_SLOTS,
    SPDM_VER_10,
    SPDM_VER_11,
    SPDM_VER_12,
    SPDM_VER_13, //
};
use crate::validator::{
    ChallengeReq,
    ChallengeRsp,
    GetCapabilitiesReq,
    GetCapabilitiesRsp,
    GetCertificateReq,
    GetCertificateRsp,
    GetDigestsReq,
    GetDigestsRsp,
    GetVersionReq,
    GetVersionRsp,
    NegotiateAlgsReq,
    NegotiateAlgsRsp,
    SpdmErrorRsp,
    SpdmHeader, //
};

const SPDM_CONTEXT: &str = "responder-challenge_auth signing";

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
/// @leaf_key: Public key portion of leaf certificate against which to check
///  responder's signatures.
/// @transcript: Concatenation of all SPDM messages exchanged during an
///  authentication or measurement sequence.  Used to verify the signature,
///  as it is computed over the hashed transcript.
/// @next_nonce: Requester nonce to be used for the next authentication
///  sequence.  Populated from user space through sysfs.
///  If user space does not provide a nonce, the kernel uses a random one.
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
    pub(crate) leaf_key: Option<*mut bindings::public_key>,

    transcript: VVec<u8>,

    pub(crate) next_nonce: KVec<u8>,
}

impl Drop for SpdmState<'_> {
    fn drop(&mut self) {
        if let Some(leaf_key) = self.leaf_key.take() {
            // SAFETY: `leaf_key` was extracted from a x509 certificate
            // in `validate_cert_chain()` so it is valid to pass to
            // `public_key_free()`.
            unsafe {
                bindings::public_key_free(leaf_key);
            }
        }

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

#[repr(C, packed)]
pub(crate) struct SpdmCertChain {
    // `length` is a u16 (with 2 bytes reserved) for SPDM versions 1.3
    // and lower and u32 for 1.4. We don't currently support `LargeOffset`
    // and `LargeLength`, so let's pretend this is always a u16
    length: u16,
    _reserved: [u8; 2],
    root_hash: bindings::__IncompleteArrayField<u8>,
    certificates: bindings::__IncompleteArrayField<u8>,
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
            leaf_key: None,
            transcript: VVec::new(),
            next_nonce: KVec::new(),
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
        &mut self,
        request_buf: &mut [u8],
        response_buf: &mut [u8],
    ) -> Result<i32, Error> {
        let header_size = core::mem::size_of::<SpdmHeader>();
        let request: &SpdmHeader = Untrusted::new(&request_buf[..]).validate()?;

        self.transcript.extend_from_slice(request_buf, GFP_KERNEL)?;

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

        self.transcript.clear();

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
        let rsp_sz = core::mem::size_of::<SpdmHeader>()
            + 2
            + response.version_number_entry_count as usize * 2;

        if rsp_sz > response_vec.len() {
            return Err(EIO);
        }

        self.transcript
            .extend_from_slice(&response_vec[..rsp_sz], GFP_KERNEL)?;

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

        if rsp_sz > response_vec.len() {
            return Err(EIO);
        }

        self.transcript
            .extend_from_slice(&response_vec[..rsp_sz], GFP_KERNEL)?;

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

        self.transcript
            .extend_from_slice(&response_vec, GFP_KERNEL)?;

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
        let rsp_sz = core::mem::size_of::<SpdmHeader>() + response.param2 as usize * self.hash_len;

        if rsp_sz > response_vec.len() {
            return Err(EIO);
        }

        self.transcript
            .extend_from_slice(&response_vec[..rsp_sz], GFP_KERNEL)?;

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

    fn get_cert_exchange<'a>(
        &mut self,
        request_buf: &mut [u8],
        response_vec: &'a mut KVec<u8>,
    ) -> Result<&'a GetCertificateRsp, Error> {
        let len = self.spdm_exchange(request_buf, response_vec.as_mut_slice())? as usize;

        // The transport must report a length within the buffer we provided.
        if len < core::mem::size_of::<GetCertificateRsp>() {
            pr_err!("Truncated certificate response\n");
            return Err(EIO);
        }
        if len > response_vec.len() {
            pr_err!("Overflowed get certificate response\n");
            return Err(EIO);
        }
        response_vec.truncate(len);

        let response: &GetCertificateRsp = Untrusted::new(response_vec.as_slice()).validate()?;
        let rsp_sz = core::mem::size_of::<SpdmHeader>() + 4 + response.portion_length as usize;

        if rsp_sz > response_vec.len() {
            return Err(EIO);
        }

        self.transcript
            .extend_from_slice(&response_vec[..rsp_sz], GFP_KERNEL)?;

        if len
            < core::mem::size_of::<GetCertificateRsp>()
                + u16::from_le(response.portion_length) as usize
        {
            pr_err!("Truncated certificate response\n");
            return Err(EIO);
        }

        Ok(response)
    }

    pub(crate) fn get_certificate(&mut self, slot: u8) -> Result<(), Error> {
        let mut request = GetCertificateReq::default();
        request.version = self.version;
        request.param1 = slot;

        let req_sz = core::mem::size_of::<GetCertificateReq>();
        let rsp_sz = (core::mem::size_of::<GetCertificateRsp>() as u32 + u16::MAX as u32)
            .min(self.transport_sz) as usize;

        request.offset = 0;
        request.length = ((rsp_sz - core::mem::size_of::<GetCertificateRsp>()) as u16).to_le();

        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let request_buf = unsafe { from_raw_parts_mut(&mut request as *mut _ as *mut u8, req_sz) };

        let mut response_vec: KVec<u8> = KVec::from_elem(0u8, rsp_sz, GFP_KERNEL)?;

        let response = self.get_cert_exchange(request_buf, &mut response_vec)?;

        if response.param1 != slot {
            pr_err!("Invalid slot response\n");
            return Err(EPROTO);
        }

        let portion_length = response.portion_length;
        let rem_length = response.remainder_length;

        let total_cert_len = u16::from_le(portion_length) as usize
            + u16::from_le(response.remainder_length) as usize;

        let mut certs_buf: KVec<u8> = KVec::new();

        certs_buf.extend_from_slice(
            &response_vec[8..(8 + u16::from_le(portion_length) as usize)],
            GFP_KERNEL,
        )?;

        let mut offset: u16 = u16::from_le(portion_length);
        let mut remainder_length = u16::from_le(rem_length) as usize;

        while remainder_length > 0 {
            request.offset = offset.to_le();
            request.length =
                ((remainder_length.min(rsp_sz - core::mem::size_of::<GetCertificateRsp>())) as u16)
                    .to_le();

            let request_buf =
                unsafe { from_raw_parts_mut(&mut request as *mut _ as *mut u8, req_sz) };

            response_vec.resize(
                request.length as usize + core::mem::size_of::<GetCertificateRsp>(),
                0,
                GFP_KERNEL,
            )?;

            let response = self.get_cert_exchange(request_buf, &mut response_vec)?;

            let portion_length = response.portion_length;
            let rem_length = response.remainder_length;

            if u16::from_le(portion_length) == 0
                || (response.param1 & 0xF) != slot
                || offset as usize
                    + u16::from_le(portion_length) as usize
                    + u16::from_le(rem_length) as usize
                    != total_cert_len
            {
                pr_err!("Malformed certificate response\n");
                return Err(EPROTO);
            }

            certs_buf.extend_from_slice(
                &response_vec[8..(8 + u16::from_le(portion_length) as usize)],
                GFP_KERNEL,
            )?;
            let (val, overflow) = offset.overflowing_add(u16::from_le(portion_length));
            if overflow {
                pr_err!("portion_length  response overflowed\n");
                return Err(EPROTO);
            }
            offset = val;
            remainder_length = u16::from_le(rem_length) as usize;
        }

        let header_length = core::mem::size_of::<SpdmCertChain>() + self.hash_len;

        if total_cert_len < header_length as usize || total_cert_len != certs_buf.len() {
            pr_err!("Malformed certificate chain in slot {slot}\n");
            return Err(EPROTO);
        }

        let cert_chain_length = {
            let ptr = certs_buf.as_ptr();
            // SAFETY: `SpdmCertChain` is repr(C) and packed. We just
            // checked the length above so we can convert it from a slice
            let ptr = ptr.cast::<SpdmCertChain>();
            // SAFETY: `ptr` came from a reference and the cast above is valid.
            let certs: &SpdmCertChain = unsafe { &*ptr };
            u16::from_le(certs.length) as usize
        };

        if total_cert_len != cert_chain_length {
            pr_err!("Malformed certificate chain in slot {slot}\n");
            return Err(EPROTO);
        }

        self.certs[slot as usize].clear();
        self.certs[slot as usize].extend_from_slice(&certs_buf, GFP_KERNEL)?;

        Ok(())
    }

    pub(crate) fn validate_cert_chain(&mut self, slot: u8) -> Result<(), Error> {
        let cert_chain_buf = &self.certs[slot as usize];
        let cert_chain_len = cert_chain_buf.len();
        // We skip over the RootHash
        let header_len = 4 + self.hash_len;

        let mut offset = header_len;
        let mut prev_cert: Option<*mut bindings::x509_certificate> = None;

        if offset >= cert_chain_len {
            return Err(EPROTO);
        }

        while offset < cert_chain_len {
            // SAFETY: `cert_chain_buf[offset..]` is a non-empty slice of
            // bytes valid for at least `cert_chain_len` bytes.
            let cert_len = unsafe {
                bindings::x509_get_certificate_length(
                    &cert_chain_buf[offset..] as *const _ as *const u8,
                    cert_chain_len - offset,
                )
            };

            if cert_len < 0 {
                pr_err!("Invalid certificate length\n");

                if let Some(prev) = prev_cert {
                    // SAFETY: `prev_cert` is the previously parsed
                    // certificate from a prior loop iteration.
                    unsafe { bindings::x509_free_certificate(prev) };
                }

                to_result(cert_len as i32)?;
            }

            // SAFETY: `cert_chain_buf[offset..]` is a non-empty slice of
            // bytes valid for at least `cert_len` bytes.
            let cert_ptr = unsafe {
                match from_err_ptr(bindings::x509_cert_parse(
                    &cert_chain_buf[offset..] as *const _ as *const c_void,
                    cert_len as usize,
                )) {
                    Err(e) => {
                        if let Some(prev) = prev_cert {
                            // SAFETY: `prev_cert` is the previously parsed
                            // certificate from a prior loop iteration.
                            bindings::x509_free_certificate(prev);
                        }
                        return Err(e);
                    }
                    Ok(c) => c,
                }
            };
            // SAFETY: Cast the `struct x509_certificate` to a Rust binding
            let cert = unsafe { *cert_ptr };

            if cert.unsupported_sig || cert.blacklisted {
                pr_err!("Certificate was rejected\n");

                if let Some(prev) = prev_cert {
                    // SAFETY: `prev_cert` is the previously parsed
                    // certificate from a prior loop iteration.
                    unsafe { bindings::x509_free_certificate(prev) };
                }
                // SAFETY: `cert_ptr` was just returned by
                // `x509_cert_parse()`.
                unsafe { bindings::x509_free_certificate(cert_ptr) };

                return Err(EKEYREJECTED);
            }

            if let Some(prev) = prev_cert {
                // SAFETY: `prev_cert` is the previously parsed
                // certificate from a prior loop iteration.
                let rc = unsafe { bindings::public_key_verify_signature((*prev).pub_, cert.sig) };

                if rc < 0 {
                    pr_err!("Signature validation error\n");

                    // SAFETY: `prev_cert` is the previously parsed
                    // certificate from a prior loop iteration.
                    unsafe { bindings::x509_free_certificate(prev) };

                    // SAFETY: `cert_ptr` was just returned by
                    // `x509_cert_parse()`.
                    unsafe { bindings::x509_free_certificate(cert_ptr) };

                    to_result(rc)?;
                }
            }

            if let Some(prev) = prev_cert {
                // SAFETY: `prev_cert` is the previously parsed
                // certificate from a prior loop iteration.
                unsafe { bindings::x509_free_certificate(prev) };
            }

            prev_cert = Some(cert_ptr);
            offset += cert_len as usize;
        }

        if let Some(prev) = prev_cert {
            if let Some(validate) = self.validate {
                // SAFETY: Call the `validate` function provided.
                let rc = unsafe { validate(self.dev, slot, prev) };
                if let Err(e) = to_result(rc) {
                    // SAFETY: `prev_cert` is the previously parsed
                    // certificate from a prior loop iteration.
                    unsafe { bindings::x509_free_certificate(prev) };
                    return Err(e);
                }
            }

            // The leaf key is the same for all slots, so just store the first one.
            if self.leaf_key.is_none() {
                // SAFETY: `prev_cert` is the previously parsed
                // certificate from a prior loop iteration.
                self.leaf_key = unsafe { Some((*prev).pub_) };
                // SAFETY: `prev_cert` is the previously parsed
                // certificate from a prior loop iteration. We are setting
                // the `pub` key to null so it isn't freed below
                unsafe { (*prev).pub_ = core::ptr::null_mut() };
            }

            // SAFETY: `prev_cert` is the previously parsed
            // certificate from a prior loop iteration.
            unsafe { bindings::x509_free_certificate(prev) };
        }

        Ok(())
    }

    pub(crate) fn challenge_rsp_len(&mut self, nonce_len: usize, opaque_len: usize) -> usize {
        // No measurement summary hash requested (MSHLength == 0)
        let mut length =
            core::mem::size_of::<SpdmHeader>() + self.hash_len + nonce_len + opaque_len + 2;

        if self.version >= SPDM_VER_13 {
            length += 8;
        }

        length + self.sig_len
    }

    fn verify_signature(&mut self, signature: &mut [u8]) -> Result<(), Error> {
        let mut sig = bindings::public_key_signature::default();
        let mut mhash: KVec<u8> = KVec::new();

        sig.s = signature as *mut _ as *mut u8;
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
            return Err(EPROTO);
        }

        if self.version <= SPDM_VER_11 {
            sig.m = m[SPDM_COMBINED_PREFIX_SZ..].as_mut_ptr();
        } else {
            let major = self.version >> 4;
            let minor = self.version & 0xF;

            let prefix = CString::try_from_fmt(fmt!("dmtf-spdm-v{major:x}.{minor:x}.*dmtf-spdm-v{major:x}.{minor:x}.*dmtf-spdm-v{major:x}.{minor:x}.*dmtf-spdm-v{major:x}.{minor:x}.*"))?;
            let mut buf = prefix.into_vec();
            let zero_pad_len = SPDM_COMBINED_PREFIX_SZ - SPDM_PREFIX_SZ - SPDM_CONTEXT.len() - 1;

            buf.extend_with(zero_pad_len, 0, GFP_KERNEL)?;
            buf.extend_from_slice(SPDM_CONTEXT.as_bytes(), GFP_KERNEL)?;

            if buf.len() != SPDM_COMBINED_PREFIX_SZ {
                pr_err!("combined_spdm_prefix calculation is incorrect");
                return Err(EPROTO);
            }

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
                return Err(EPROTO);
            }

            sig.m = mhash.as_mut_ptr();
        }

        sig.m_size = self.hash_len as u32;

        if let Some(leaf_key) = self.leaf_key {
            unsafe { to_result(bindings::public_key_verify_signature(leaf_key, &sig)) }
        } else {
            return Err(EPROTO);
        }
    }

    pub(crate) fn challenge(&mut self, slot: u8) -> Result<(), Error> {
        let mut request = ChallengeReq::default();
        request.version = self.version;
        request.param1 = slot;

        let nonce_len = request.nonce.len();

        if self.next_nonce.len() > 0 {
            let request_nonce_len = request.nonce.len();

            if self.next_nonce.len() == request_nonce_len {
                request
                    .nonce
                    .copy_from_slice(&self.next_nonce[..request_nonce_len]);
            } else {
                return Err(EINVAL);
            }

            self.next_nonce.clear();
        } else {
            unsafe {
                bindings::get_random_bytes(&mut request.nonce as *mut _ as *mut c_void, nonce_len)
            };
        }

        let req_sz = if self.version <= SPDM_VER_12 {
            offset_of!(ChallengeReq, context)
        } else {
            core::mem::size_of::<ChallengeReq>()
        };

        let rsp_sz = self.challenge_rsp_len(nonce_len, SPDM_MAX_OPAQUE_DATA);

        // SAFETY: `request` is repr(C) and packed, so we can convert it to a slice
        let request_buf = unsafe { from_raw_parts_mut(&mut request as *mut _ as *mut u8, req_sz) };

        let mut response_vec: KVec<u8> = KVec::from_elem(0u8, rsp_sz, GFP_KERNEL)?;

        let rc = self.spdm_exchange(request_buf, response_vec.as_mut_slice())? as usize;

        // The transport must report a length within the buffer we provided.
        if rc < core::mem::size_of::<ChallengeRsp>() {
            pr_err!("Truncated challenge response\n");
            return Err(EIO);
        }
        response_vec.truncate(rc);

        let _response: &ChallengeRsp = Untrusted::new(response_vec.as_slice()).validate()?;

        // MSHLength is 0 as no measurement summary hash requested
        let opaque_len_offset = core::mem::size_of::<SpdmHeader>() + self.hash_len + nonce_len;

        if opaque_len_offset + 2 > response_vec.len() {
            return Err(EIO);
        }

        let opaque_len = u16::from_le_bytes(
            response_vec[opaque_len_offset..(opaque_len_offset + 2)]
                .try_into()
                .unwrap_or([0, 0]),
        );

        let rsp_sz = self.challenge_rsp_len(nonce_len, opaque_len as usize);

        if rsp_sz > response_vec.len() {
            pr_err!("Truncated challenge response\n");
            return Err(EIO);
        }

        self.transcript
            .extend_from_slice(&response_vec[..rsp_sz], GFP_KERNEL)?;

        /* Verify signature at end of transcript against leaf key */
        let sig_start = rsp_sz - self.sig_len;
        let signature = &mut response_vec[sig_start..rsp_sz];

        match self.verify_signature(signature) {
            Ok(()) => {
                pr_info!("Authenticated with certificate slot {slot}\n");
                Ok(())
            }
            Err(e) => {
                pr_err!("Cannot verify challenge_auth signature: {e:?}\n");
                Err(EPROTO)
            }
        }
    }
}
