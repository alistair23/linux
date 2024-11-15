// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Western Digital

//! Constants used by the library
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

/* SPDM versions supported by this implementation */
pub(crate) const SPDM_VER_10: u8 = 0x10;

pub(crate) const SPDM_MIN_VER: u8 = SPDM_VER_10;

pub(crate) const SPDM_REQ: u8 = 0x80;
pub(crate) const SPDM_ERROR: u8 = 0x7f;

#[expect(dead_code)]
#[derive(Clone, Copy)]
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

impl core::fmt::LowerHex for SpdmErrorCode {
    /// A debug print format for the SpdmSessionInfo struct
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "{:#x}", *self as u8)?;

        Ok(())
    }
}
