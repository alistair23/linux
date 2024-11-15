// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Western Digital

//! Related structs and their Validate implementations.
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use crate::bindings::{
    __IncompleteArrayField,
    __le16, //
};
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

use crate::consts::{
    SPDM_GET_VERSION,
    SPDM_MIN_VER, //
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

#[repr(C, packed)]
pub(crate) struct GetVersionReq {
    pub(crate) version: u8,
    pub(crate) code: u8,
    pub(crate) param1: u8,
    pub(crate) param2: u8,
}

impl Default for GetVersionReq {
    fn default() -> Self {
        GetVersionReq {
            version: 0,
            code: SPDM_GET_VERSION,
            param1: 0,
            param2: 0,
        }
    }
}

#[repr(C, packed)]
pub(crate) struct GetVersionRsp {
    pub(crate) version: u8,
    pub(crate) code: u8,
    param1: u8,
    param2: u8,
    reserved: u8,
    pub(crate) version_number_entry_count: u8,
    pub(crate) version_number_entries: __IncompleteArrayField<__le16>,
}

impl<'a> Validate<Untrusted<&'a [u8]>> for &'a GetVersionRsp {
    type Err = Error;

    fn validate(unvalidated: &[u8]) -> Result<Self, Self::Err> {
        if unvalidated.len() < mem::size_of::<GetVersionRsp>() {
            return Err(EINVAL);
        }

        let version = *(unvalidated.get(0).ok_or(ENOMEM))? as usize;
        if version != SPDM_MIN_VER.into() {
            return Err(EINVAL);
        }

        let version_number_entries = *(unvalidated.get(5).ok_or(ENOMEM))? as usize;
        let total_expected_size =
            version_number_entries * mem::size_of::<__le16>() + mem::size_of::<GetVersionRsp>();
        if unvalidated.len() < total_expected_size {
            return Err(EINVAL);
        }

        let ptr = unvalidated.as_ptr();
        // CAST: `GetVersionRsp` only contains integers and has `repr(C)`.
        let ptr = ptr.cast::<GetVersionRsp>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        let rsp: &GetVersionRsp = unsafe { &*ptr };

        Ok(rsp)
    }
}
