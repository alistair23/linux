// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Western Digital

//! Related structs and their Validate implementations.
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use crate::consts::SpdmErrorCode;
use core::mem;
use kernel::prelude::*;
use kernel::{
    error::{
        code::EINVAL,
        Error, //
    },
    validate::{
        Untrusted,
        Validate, //
    },
};

#[repr(C, packed)]
pub(crate) struct SpdmHeader {
    pub(crate) version: u8,
    pub(crate) code: u8, /* RequestResponseCode */
    pub(crate) param1: u8,
    pub(crate) param2: u8,
}

impl Validate<Untrusted<&[u8]>> for &SpdmHeader {
    type Err = Error;

    fn validate(unvalidated: &[u8]) -> Result<Self, Self::Err> {
        if unvalidated.len() < mem::size_of::<SpdmHeader>() {
            return Err(EINVAL);
        }

        let ptr = unvalidated.as_ptr();
        // CAST: `SpdmHeader` only contains integers and has `repr(C)`.
        let ptr = ptr.cast::<SpdmHeader>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        Ok(unsafe { &*ptr })
    }
}

impl Validate<Untrusted<&mut [u8]>> for &mut SpdmHeader {
    type Err = Error;

    fn validate(unvalidated: &mut [u8]) -> Result<Self, Self::Err> {
        if unvalidated.len() < mem::size_of::<SpdmHeader>() {
            return Err(EINVAL);
        }

        let ptr = unvalidated.as_mut_ptr();
        // CAST: `SpdmHeader` only contains integers and has `repr(C, packed)`.
        let ptr = ptr.cast::<SpdmHeader>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        Ok(unsafe { &mut *ptr })
    }
}

#[repr(C, packed)]
pub(crate) struct SpdmErrorRsp {
    pub(crate) version: u8,
    /// This will always be SPDM_ERROR (0x7F)
    pub(crate) code: u8,
    pub(crate) error_code: SpdmErrorCode,
    pub(crate) error_data: u8,
}

impl<'a> Validate<Untrusted<&'a [u8]>> for &'a SpdmErrorRsp {
    type Err = Error;

    fn validate(unvalidated: &[u8]) -> Result<Self, Self::Err> {
        if unvalidated.len() < mem::size_of::<SpdmErrorRsp>() {
            return Err(EINVAL);
        }

        // Reject responses whose `error_code` byte is not a known
        // `SpdmErrorCode` discriminant before exposing the struct to callers.
        SpdmErrorCode::try_from(unvalidated[mem::offset_of!(SpdmErrorRsp, error_code)])?;

        let ptr = unvalidated.as_ptr();
        // CAST: `SpdmErrorRsp` only contains `u8` fields and `SpdmErrorCode` which
        // we have already checked and has `repr(C, packed)`.
        let ptr = ptr.cast::<SpdmErrorRsp>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        Ok(unsafe { &*ptr })
    }
}
