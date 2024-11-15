// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Western Digital

//! Related structs and their Validate implementations.
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use crate::bindings::{__IncompleteArrayField, __le16};
use crate::consts::SpdmErrorCode;
use core::mem;
use kernel::prelude::*;
use kernel::{
    error::{code::EINVAL, Error},
    validate::{Unvalidated, Validate},
};

use crate::consts::SPDM_GET_VERSION;

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

impl Validate<&mut Unvalidated<KVec<u8>>> for &mut GetVersionRsp {
    type Err = Error;

    fn validate(unvalidated: &mut Unvalidated<KVec<u8>>) -> Result<Self, Self::Err> {
        let raw = unvalidated.raw_mut();
        if raw.len() < mem::size_of::<GetVersionRsp>() {
            return Err(EINVAL);
        }

        let version_number_entries = *(raw.get(5).ok_or(ENOMEM))? as usize;
        let total_expected_size = version_number_entries * 2 + 6;
        if raw.len() < total_expected_size {
            return Err(EINVAL);
        }

        let ptr = raw.as_mut_ptr();
        // CAST: `GetVersionRsp` only contains integers and has `repr(C)`.
        let ptr = ptr.cast::<GetVersionRsp>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        let rsp: &mut GetVersionRsp = unsafe { &mut *ptr };

        // Creating a reference on a packed struct will result in
        // undefined behaviour, so we operate on the raw data directly
        let unaligned = core::ptr::addr_of_mut!(rsp.version_number_entries) as *mut u16;
        for version_offset in 0..version_number_entries {
            let addr = unaligned.wrapping_add(version_offset);
            let version = unsafe { core::ptr::read_unaligned::<u16>(addr) };
            unsafe { core::ptr::write_unaligned::<u16>(addr, version.to_le()) }
        }

        Ok(rsp)
    }
}
