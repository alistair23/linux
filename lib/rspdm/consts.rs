// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Western Digital

//! Constants used by the library
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use crate::validator::GetVersionRsp;
use core::mem;
use kernel::bits::bit_u32;
use kernel::error::{code::EINVAL, Error};

// SPDM versions supported by this implementation
pub(crate) const SPDM_VER_10: u8 = 0x10;
pub(crate) const SPDM_VER_11: u8 = 0x11;
pub(crate) const SPDM_VER_12: u8 = 0x12;
#[allow(dead_code)]
pub(crate) const SPDM_VER_13: u8 = 0x13;
pub(crate) const SPDM_VER_14: u8 = 0x14;

pub(crate) const SPDM_MIN_VER: u8 = SPDM_VER_10;
pub(crate) const SPDM_MAX_VER: u8 = SPDM_VER_14;

pub(crate) const SPDM_REQ: u8 = 0x80;
pub(crate) const SPDM_ERROR: u8 = 0x7f;

#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum SpdmErrorCode {
    InvalidRequest = 0x01,
    /// This was removed in version 1.2.0 and is now reserved
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
    RequestSessionTerminated = 0x46,
    InvalidState = 0x47,
    VendorDefinedError = 0xff,
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
            _ => return Err(EINVAL),
        })
    }
}

impl core::fmt::LowerHex for SpdmErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#x}", *self as u8)
    }
}

pub(crate) const SPDM_GET_VERSION: u8 = 0x84;
pub(crate) const SPDM_GET_VERSION_LEN: usize =
    mem::size_of::<GetVersionRsp>() + (u8::MAX as usize) * mem::size_of::<u16>();

pub(crate) const SPDM_GET_CAPABILITIES: u8 = 0xe1;
pub(crate) const SPDM_MIN_DATA_TRANSFER_SIZE: u32 = 42;

// SPDM cryptographic timeout of this implementation:
// Assume calculations may take up to 1 sec on a busy machine, which equals
// roughly 1 << 20.  That's within the limits mandated for responders by CMA
// (1 << 23 usec, PCIe r6.2 sec 6.31.3) and DOE (1 sec, PCIe r6.2 sec 6.30.2).
// Used in GET_CAPABILITIES exchange.
pub(crate) const SPDM_CTEXPONENT: u8 = 20;

pub(crate) const SPDM_CERT_CAP: u32 = bit_u32(1);
pub(crate) const SPDM_CHAL_CAP: u32 = bit_u32(2);

pub(crate) const SPDM_REQ_CAPS: u32 = SPDM_CERT_CAP | SPDM_CHAL_CAP;
pub(crate) const SPDM_RSP_MIN_CAPS: u32 = SPDM_CERT_CAP | SPDM_CHAL_CAP;
