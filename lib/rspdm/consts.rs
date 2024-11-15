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
#[allow(dead_code)]
pub(crate) const SPDM_VER_11: u8 = 0x11;
#[allow(dead_code)]
pub(crate) const SPDM_VER_12: u8 = 0x12;
pub(crate) const SPDM_VER_13: u8 = 0x13;

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

pub(crate) const SPDM_GET_VERSION: u8 = 0x84;
pub(crate) const SPDM_GET_VERSION_LEN: usize = mem::size_of::<SpdmHeader>() + 255;
