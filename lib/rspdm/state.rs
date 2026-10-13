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
    hash::Shash,
    str::CStr,
    validate::Untrusted,
};

use crate::consts::{
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
    /// Cached capabilities of responder. Received during GET_CAPABILITIES
    /// exchange.
    pub(crate) rsp_caps: u32,
    /// Asymmetric key algorithm for signature verification of CHALLENGE_AUTH
    /// and MEASUREMENTS messages. Selected by responder during
    /// NEGOTIATE_ALGORITHMS exchange.
    pub(crate) base_asym_alg: u32,
    /// Hash algorithm for signature verification of CHALLENGE_AUTH and
    /// MEASUREMENTS messages. Selected by responder during
    /// NEGOTIATE_ALGORITHMS exchange.
    pub(crate) base_hash_alg: u32,
    /// Hash algorithm for measurement blocks. Selected by responder during
    /// NEGOTIATE_ALGORITHMS exchange.
    pub(crate) meas_hash_alg: u32,

    /// Human-readable name of `base_asym_alg`'s signature encoding. Passed
    /// to the crypto subsystem when calling `verify_signature()`.
    base_asym_enc: &'static CStr,
    /// Signature length of `base_asym_alg` (in bytes). S or SigLen in SPDM
    /// specification.
    sig_len: usize,

    /// Hash transformation for `base_hash_alg` computation.
    crypto: Option<Shash>,
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
            rsp_caps: 0,
            base_asym_alg: 0,
            base_hash_alg: 0,
            meas_hash_alg: 0,
            base_asym_enc: c"",
            sig_len: 0,
            crypto: None,
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

                (GET_CAPABILITIES_RSP_SZ as u32 + u32::from(u16::MAX)).min(self.transport_sz)
                    as usize
            }
        };

        let mut request_buf = request.to_bytes()?;

        let response_vec: KVec<u8> = KVec::from_elem(0u8, rsp_sz, GFP_KERNEL)?;

        let response: GetCapabilitiesRsp = self
            .spdm_exchange(request_buf.as_mut_slice(), response_vec)?
            .validate(&*self)?;

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
            self.transport_sz = self.transport_sz.min(response.data_transfer_size);
        }

        Ok(())
    }

    fn update_response_algs(&mut self) -> Result<(), Error> {
        match self.base_asym_alg {
            #[cfg(CONFIG_CRYPTO_RSA)]
            SPDM_ASYM_RSASSA_2048 => {
                self.sig_len = 256;
                self.base_asym_enc = c"pkcs1";
            }
            #[cfg(CONFIG_CRYPTO_RSA)]
            SPDM_ASYM_RSASSA_3072 => {
                self.sig_len = 384;
                self.base_asym_enc = c"pkcs1";
            }
            #[cfg(CONFIG_CRYPTO_RSA)]
            SPDM_ASYM_RSASSA_4096 => {
                self.sig_len = 512;
                self.base_asym_enc = c"pkcs1";
            }
            #[cfg(CONFIG_CRYPTO_ECDSA)]
            SPDM_ASYM_ECDSA_ECC_NIST_P256 => {
                self.sig_len = 64;
                self.base_asym_enc = c"p1363";
            }
            #[cfg(CONFIG_CRYPTO_ECDSA)]
            SPDM_ASYM_ECDSA_ECC_NIST_P384 => {
                self.sig_len = 96;
                self.base_asym_enc = c"p1363";
            }
            #[cfg(CONFIG_CRYPTO_ECDSA)]
            SPDM_ASYM_ECDSA_ECC_NIST_P521 => {
                self.sig_len = 132;
                self.base_asym_enc = c"p1363";
            }
            _ => {
                pr_err!("Unknown asym algorithm\n");
                return Err(EPROTO);
            }
        }

        let hash_name = match self.base_hash_alg {
            #[cfg(CONFIG_CRYPTO_SHA256)]
            SPDM_HASH_SHA_256 => c"sha256",
            #[cfg(CONFIG_CRYPTO_SHA512)]
            SPDM_HASH_SHA_384 => c"sha384",
            #[cfg(CONFIG_CRYPTO_SHA512)]
            SPDM_HASH_SHA_512 => c"sha512",
            _ => {
                pr_err!("Unknown hash algorithm\n");
                return Err(EPROTO);
            }
        };

        self.crypto = Some(Shash::new(hash_name)?);

        Ok(())
    }

    pub(crate) fn negotiate_algs(&mut self) -> Result<(), Error> {
        let mut request = NegotiateAlgsReq::default();
        request.header.version = self.version;

        if self.version >= SPDM_VER_12 && (self.rsp_caps & SPDM_KEY_EX_CAP) == SPDM_KEY_EX_CAP {
            request.other_params_support = SPDM_OPAQUE_DATA_FMT_GENERAL;
        }

        let rsp_sz =
            (NEGOTIATE_ALGS_RSP_SZ as u32 + u32::from(u16::MAX)).min(self.transport_sz) as usize;

        request.length = NegotiateAlgsReq::WIRE_SIZE as u16;

        let mut request_buf = request.to_bytes()?;

        let response_vec: KVec<u8> = KVec::from_elem(0u8, rsp_sz, GFP_KERNEL)?;

        let response: NegotiateAlgsRsp = self
            .spdm_exchange(request_buf.as_mut_slice(), response_vec)?
            .validate(&*self)?;

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
            || response.other_params_sel != request.other_params_support
        {
            pr_err!("Malformed algorithms response\n");
            return Err(EPROTO);
        }

        self.update_response_algs()?;

        Ok(())
    }
}
