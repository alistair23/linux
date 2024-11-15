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
    error::{code::EINVAL, Error},
    validate::{Unvalidated, Validate},
};

#[repr(C, packed)]
pub(crate) struct SpdmHeader {
    pub(crate) version: u8,
    pub(crate) code: u8, /* RequestResponseCode */
    pub(crate) param1: u8,
    pub(crate) param2: u8,
}

impl Validate<&Unvalidated<[u8]>> for &SpdmHeader {
    type Err = Error;

    fn validate(unvalidated: &Unvalidated<[u8]>) -> Result<Self, Self::Err> {
        let raw = unvalidated.raw();
        if raw.len() < mem::size_of::<SpdmHeader>() {
            return Err(EINVAL);
        }

        let ptr = raw.as_ptr();
        // CAST: `SpdmHeader` only contains integers and has `repr(C)`.
        let ptr = ptr.cast::<SpdmHeader>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        Ok(unsafe { &*ptr })
    }
}

impl Validate<&mut Unvalidated<[u8]>> for &mut SpdmHeader {
    type Err = Error;

    fn validate(unvalidated: &mut Unvalidated<[u8]>) -> Result<Self, Self::Err> {
        let raw = unvalidated.raw_mut();
        if raw.len() < mem::size_of::<SpdmHeader>() {
            return Err(EINVAL);
        }

        let ptr = raw.as_mut_ptr();
        // CAST: `SpdmHeader` only contains integers and has `repr(C)`.
        let ptr = ptr.cast::<SpdmHeader>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        Ok(unsafe { &mut *ptr })
    }
}

#[repr(C, packed)]
pub(crate) struct SpdmErrorRsp {
    pub(crate) version: u8,
    pub(crate) code: u8,
    pub(crate) error_code: SpdmErrorCode,
    pub(crate) error_data: u8,
}
