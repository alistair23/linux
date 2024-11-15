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
        Unvalidated,
        Validate, //
    },
};

use crate::consts::{
    SPDM_CTEXPONENT,
    SPDM_GET_CAPABILITIES,
    SPDM_GET_VERSION,
    SPDM_MIN_VER,
    SPDM_REQ_CAPS, //
    SPDM_VER_11,
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
    /// This will always be SPDM_ERROR (0x7F)
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

        let version = *(raw.get(0).ok_or(ENOMEM))? as usize;
        if version != SPDM_MIN_VER.into() {
            return Err(EINVAL);
        }

        let version_number_entries = *(raw.get(5).ok_or(ENOMEM))? as usize;
        let total_expected_size =
            version_number_entries * mem::size_of::<__le16>() + mem::size_of::<GetVersionRsp>();
        if raw.len() < total_expected_size {
            return Err(EINVAL);
        }

        let ptr = raw.as_mut_ptr();
        // CAST: `GetVersionRsp` only contains integers and has `repr(C)`.
        let ptr = ptr.cast::<GetVersionRsp>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        let rsp: &mut GetVersionRsp = unsafe { &mut *ptr };

        Ok(rsp)
    }
}

#[repr(C, packed)]
pub(crate) struct GetCapabilitiesReq {
    pub(crate) version: u8,
    pub(crate) code: u8,
    pub(crate) param1: u8,
    pub(crate) param2: u8,

    reserved1: u8,
    pub(crate) ctexponent: u8,
    reserved2: [u8; 2],

    pub(crate) flags: u32,

    /* End of SPDM 1.1 structure */
    pub(crate) data_transfer_size: u32,
    pub(crate) max_spdm_msg_size: u32,
}

impl Default for GetCapabilitiesReq {
    fn default() -> Self {
        GetCapabilitiesReq {
            version: 0,
            code: SPDM_GET_CAPABILITIES,
            param1: 0,
            param2: 0,
            reserved1: 0,
            ctexponent: SPDM_CTEXPONENT,
            reserved2: [0; 2],
            flags: (SPDM_REQ_CAPS as u32).to_le(),
            data_transfer_size: 0,
            max_spdm_msg_size: 0,
        }
    }
}

#[repr(C, packed)]
pub(crate) struct GetCapabilitiesRsp {
    pub(crate) version: u8,
    pub(crate) code: u8,
    pub(crate) param1: u8,
    param2: u8,

    reserved1: u8,
    pub(crate) ctexponent: u8,
    reserved2: [u8; 2],

    pub(crate) flags: u32,

    /* End of SPDM 1.1 structure */
    pub(crate) data_transfer_size: u32,
    pub(crate) max_spdm_msg_size: u32,

    pub(crate) supported_algorithms: __IncompleteArrayField<__le16>,
}

impl Validate<&mut Unvalidated<KVec<u8>>> for &mut GetCapabilitiesRsp {
    type Err = Error;

    fn validate(unvalidated: &mut Unvalidated<KVec<u8>>) -> Result<Self, Self::Err> {
        let raw = unvalidated.raw_mut();

        if raw.len() < mem::size_of::<GetCapabilitiesRsp>() {
            let version = *(raw.get(0).ok_or(ENOMEM))?;
            let version_1_1_len = mem::size_of::<GetCapabilitiesRsp>()
                - mem::size_of::<__IncompleteArrayField<__le16>>()
                - mem::size_of::<u32>()
                - mem::size_of::<u32>();

            if version == SPDM_VER_11 && raw.len() == version_1_1_len {
                // Version 1.1 of the spec doesn't include all of the fields
                // So let's extend the KVec with 0s so we can cast the
                // vector to GetCapabilitiesRsp

                for _i in version_1_1_len..mem::size_of::<GetCapabilitiesRsp>() {
                    raw.push(0, GFP_KERNEL)?;
                }
            } else {
                return Err(EINVAL);
            }
        }

        let ptr = raw.as_mut_ptr();
        // CAST: `GetCapabilitiesRsp` only contains integers and has `repr(C)`.
        let ptr = ptr.cast::<GetCapabilitiesRsp>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        let rsp: &mut GetCapabilitiesRsp = unsafe { &mut *ptr };

        Ok(rsp)
    }
}
