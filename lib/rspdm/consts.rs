// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Western Digital

//! Constants used by the library
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use crate::validator::SpdmHeader;
use core::mem;

/* SPDM versions supported by this implementation */
pub(crate) const SPDM_VER_10: u8 = 0x10;
pub(crate) const SPDM_VER_11: u8 = 0x11;
pub(crate) const SPDM_VER_12: u8 = 0x12;
pub(crate) const SPDM_VER_13: u8 = 0x13;

pub(crate) const SPDM_SLOTS: usize = 8;

pub(crate) const SPDM_MIN_VER: u8 = SPDM_VER_10;
pub(crate) const SPDM_MAX_VER: u8 = SPDM_VER_13;

pub(crate) const SPDM_REQ: u8 = 0x80;
pub(crate) const SPDM_ERROR: u8 = 0x7f;

#[expect(dead_code)]
#[derive(Clone, Copy)]
pub(crate) enum SpdmErrorCode {
    InvalidRequest = 0x01,
    InvalidSession = 0x02,
    Busy = 0x03,
    UnexpectedRequest = 0x04,
    Unspecified = 0x05,
    DecryptError = 0x06,
    UnsupportedRequest = 0x07,
    RequestInFlight = 0x08,
    InvalidResponseCode = 0x09,
    SessionLimitExceeded = 0x0a,
    SessionRequired = 0x0b,
    ResetRequired = 0x0c,
    ResponseTooLarge = 0x0d,
    RequestTooLarge = 0x0e,
    LargeResponse = 0x0f,
    MessageLost = 0x10,
    InvalidPolicy = 0x11,
    VersionMismatch = 0x41,
    ResponseNotReady = 0x42,
    RequestResynch = 0x43,
    OperationFailed = 0x44,
    NoPendingRequests = 0x45,
    VendorDefinedError = 0xff,
}

impl core::fmt::LowerHex for SpdmErrorCode {
    /// A debug print format for the SpdmSessionInfo struct
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SpdmErrorCode::InvalidRequest => {
                writeln!(f, "0x01")?;
            }
            SpdmErrorCode::InvalidSession => {
                writeln!(f, "0x02")?;
            }
            SpdmErrorCode::Busy => {
                writeln!(f, "0x03")?;
            }
            SpdmErrorCode::UnexpectedRequest => {
                writeln!(f, "0x04")?;
            }
            SpdmErrorCode::Unspecified => {
                writeln!(f, "0x05")?;
            }
            SpdmErrorCode::DecryptError => {
                writeln!(f, "0x06")?;
            }
            SpdmErrorCode::UnsupportedRequest => {
                writeln!(f, "0x07")?;
            }
            SpdmErrorCode::RequestInFlight => {
                writeln!(f, "0x08")?;
            }
            SpdmErrorCode::InvalidResponseCode => {
                writeln!(f, "0x09")?;
            }
            SpdmErrorCode::SessionLimitExceeded => {
                writeln!(f, "0x0a")?;
            }
            SpdmErrorCode::SessionRequired => {
                writeln!(f, "0x0b")?;
            }
            SpdmErrorCode::ResetRequired => {
                writeln!(f, "0x0c")?;
            }
            SpdmErrorCode::ResponseTooLarge => {
                writeln!(f, "0x0d")?;
            }
            SpdmErrorCode::RequestTooLarge => {
                writeln!(f, "0x0e")?;
            }
            SpdmErrorCode::LargeResponse => {
                writeln!(f, "0x0f")?;
            }
            SpdmErrorCode::MessageLost => {
                writeln!(f, "0x10")?;
            }
            SpdmErrorCode::InvalidPolicy => {
                writeln!(f, "0x11")?;
            }
            SpdmErrorCode::VersionMismatch => {
                writeln!(f, "0x41")?;
            }
            SpdmErrorCode::ResponseNotReady => {
                writeln!(f, "0x42")?;
            }
            SpdmErrorCode::RequestResynch => {
                writeln!(f, "0x43")?;
            }
            SpdmErrorCode::OperationFailed => {
                writeln!(f, "0x44")?;
            }
            SpdmErrorCode::NoPendingRequests => {
                writeln!(f, "0x45")?;
            }
            SpdmErrorCode::VendorDefinedError => {
                writeln!(f, "0xff")?;
            }
        }
        Ok(())
    }
}

pub(crate) const SPDM_GET_VERSION: u8 = 0x84;
pub(crate) const SPDM_GET_VERSION_LEN: usize = mem::size_of::<SpdmHeader>() + 255;

pub(crate) const SPDM_GET_CAPABILITIES: u8 = 0xe1;
pub(crate) const SPDM_MIN_DATA_TRANSFER_SIZE: u32 = 42;

// SPDM cryptographic timeout of this implementation:
// Assume calculations may take up to 1 sec on a busy machine, which equals
// roughly 1 << 20.  That's within the limits mandated for responders by CMA
// (1 << 23 usec, PCIe r6.2 sec 6.31.3) and DOE (1 sec, PCIe r6.2 sec 6.30.2).
// Used in GET_CAPABILITIES exchange.
pub(crate) const SPDM_CTEXPONENT: u8 = 20;

pub(crate) const SPDM_CERT_CAP: u32 = 1 << 1;
pub(crate) const SPDM_CHAL_CAP: u32 = 1 << 2;
pub(crate) const SPDM_MEAS_CAP_MASK: u32 = 3 << 3;
pub(crate) const SPDM_KEY_EX_CAP: u32 = 1 << 9;

pub(crate) const SPDM_REQ_CAPS: u32 = SPDM_CERT_CAP | SPDM_CHAL_CAP;
pub(crate) const SPDM_RSP_MIN_CAPS: u32 = SPDM_CERT_CAP | SPDM_CHAL_CAP;

pub(crate) const SPDM_NEGOTIATE_ALGS: u8 = 0xe3;

pub(crate) const SPDM_MEAS_SPEC_DMTF: u8 = 1 << 0;

pub(crate) const SPDM_ASYM_RSASSA_2048: u32 = 1 << 0;
pub(crate) const _SPDM_ASYM_RSAPSS_2048: u32 = 1 << 1;
pub(crate) const SPDM_ASYM_RSASSA_3072: u32 = 1 << 2;
pub(crate) const _SPDM_ASYM_RSAPSS_3072: u32 = 1 << 3;
pub(crate) const SPDM_ASYM_ECDSA_ECC_NIST_P256: u32 = 1 << 4;
pub(crate) const SPDM_ASYM_RSASSA_4096: u32 = 1 << 5;
pub(crate) const _SPDM_ASYM_RSAPSS_4096: u32 = 1 << 6;
pub(crate) const SPDM_ASYM_ECDSA_ECC_NIST_P384: u32 = 1 << 7;
pub(crate) const SPDM_ASYM_ECDSA_ECC_NIST_P521: u32 = 1 << 8;
pub(crate) const _SPDM_ASYM_SM2_ECC_SM2_P256: u32 = 1 << 9;
pub(crate) const _SPDM_ASYM_EDDSA_ED25519: u32 = 1 << 10;
pub(crate) const _SPDM_ASYM_EDDSA_ED448: u32 = 1 << 11;

pub(crate) const SPDM_HASH_SHA_256: u32 = 1 << 0;
pub(crate) const SPDM_HASH_SHA_384: u32 = 1 << 1;
pub(crate) const SPDM_HASH_SHA_512: u32 = 1 << 2;

pub(crate) const SPDM_GET_DIGESTS: u8 = 0x81;

#[cfg(CONFIG_CRYPTO_RSA)]
pub(crate) const SPDM_ASYM_RSA: u32 =
    SPDM_ASYM_RSASSA_2048 | SPDM_ASYM_RSASSA_3072 | SPDM_ASYM_RSASSA_4096;
#[cfg(not(CONFIG_CRYPTO_RSA))]
pub(crate) const SPDM_ASYM_RSA: u32 = 0;

#[cfg(CONFIG_CRYPTO_ECDSA)]
pub(crate) const SPDM_ASYM_ECDSA: u32 =
    SPDM_ASYM_ECDSA_ECC_NIST_P256 | SPDM_ASYM_ECDSA_ECC_NIST_P384 | SPDM_ASYM_ECDSA_ECC_NIST_P521;
#[cfg(not(CONFIG_CRYPTO_ECDSA))]
pub(crate) const SPDM_ASYM_ECDSA: u32 = 0;

#[cfg(CONFIG_CRYPTO_SHA256)]
pub(crate) const SPDM_HASH_SHA2_256: u32 = SPDM_HASH_SHA_256;
#[cfg(not(CONFIG_CRYPTO_SHA256))]
pub(crate) const SPDM_HASH_SHA2_256: u32 = 0;

#[cfg(CONFIG_CRYPTO_SHA512)]
pub(crate) const SPDM_HASH_SHA2_384_512: u32 = SPDM_HASH_SHA_384 | SPDM_HASH_SHA_512;
#[cfg(not(CONFIG_CRYPTO_SHA512))]
pub(crate) const SPDM_HASH_SHA2_384_512: u32 = 0;

pub(crate) const SPDM_ASYM_ALGOS: u32 = SPDM_ASYM_RSA | SPDM_ASYM_ECDSA;
pub(crate) const SPDM_HASH_ALGOS: u32 = SPDM_HASH_SHA2_256 | SPDM_HASH_SHA2_384_512;

/* Maximum number of ReqAlgStructs sent by this implementation */
// pub(crate) const SPDM_MAX_REQ_ALG_STRUCT: usize = 4;

pub(crate) const SPDM_OPAQUE_DATA_FMT_GENERAL: u8 = 1 << 1;
