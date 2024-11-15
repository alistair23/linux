// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Western Digital

//! Constants used by the library
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

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
