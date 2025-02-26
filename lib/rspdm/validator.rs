// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Western Digital

//! Related structs and their Validate implementations.
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use crate::bindings::{
    __IncompleteArrayField,
    __le16,
    __le32, //
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
    SPDM_ASYM_ALGOS,
    SPDM_CTEXPONENT,
    SPDM_GET_CAPABILITIES,
    SPDM_GET_DIGESTS,
    SPDM_GET_VERSION,
    SPDM_HASH_ALGOS,
    SPDM_MEAS_SPEC_DMTF,
    SPDM_MIN_VER,
    SPDM_NEGOTIATE_ALGS,
    SPDM_REQ_CAPS,
    SPDM_VER_10,
    SPDM_VER_11, //
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
            flags: SPDM_REQ_CAPS.to_le(),
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

impl<'a> Validate<Untrusted<&'a mut KVec<u8>>> for &'a mut GetCapabilitiesRsp {
    type Err = Error;

    fn validate(unvalidated: &mut KVec<u8>) -> Result<Self, Self::Err> {
        let version = *(unvalidated.get(0).ok_or(EINVAL))?;

        let expected_length = match version {
            SPDM_VER_10 | SPDM_VER_11 => {
                core::mem::size_of::<SpdmHeader>() + 4 + core::mem::size_of::<u32>()
            }
            _ => {
                // Check to see if param1 is set
                if *(unvalidated.get(2).ok_or(EINVAL))? == 0 {
                    mem::size_of::<GetCapabilitiesRsp>()
                        - mem::size_of::<__IncompleteArrayField<__le16>>()
                } else {
                    // Not currently supported by Linux, we don't set the bit
                    // so the responder shouldn't either.
                    return Err(EINVAL);
                }
            }
        };

        // Make sure the response meets the SPDM spec version requirements
        if unvalidated.len() < expected_length {
            return Err(EINVAL);
        }

        // If the response is shorter than GetCapabilitiesRsp
        // (which is valid for older spec versions and when param1 is
        // set to 0) then we need to pad the vector to ensure
        // GetCapabilitiesRsp will be initialised.
        while unvalidated.len() < mem::size_of::<GetCapabilitiesRsp>() {
            unvalidated.push(0, GFP_KERNEL)?;
        }

        let ptr = unvalidated.as_mut_ptr();
        // CAST: `GetCapabilitiesRsp` only contains integers and has `repr(C)`.
        let ptr = ptr.cast::<GetCapabilitiesRsp>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        let rsp: &mut GetCapabilitiesRsp = unsafe { &mut *ptr };

        Ok(rsp)
    }
}

#[repr(C, packed)]
pub(crate) struct RegAlg {
    pub(crate) alg_type: u8,
    pub(crate) alg_count: u8,
    pub(crate) alg_supported: u16,
    pub(crate) alg_external: __IncompleteArrayField<__le32>,
}

#[repr(C, packed)]
pub(crate) struct NegotiateAlgsReq {
    pub(crate) version: u8,
    pub(crate) code: u8,
    pub(crate) param1: u8, // size of resp_alg_struct
    param2: u8,

    pub(crate) length: u16,
    pub(crate) measurement_specification: u8,
    pub(crate) other_params_support: u8,

    pub(crate) base_asym_algo: u32,
    pub(crate) base_hash_algo: u32,

    reserved1: [u8; 12],

    pub(crate) ext_asym_count: u8,
    pub(crate) ext_hash_count: u8,
    reserved2: u8,
    pub(crate) mel_specification: u8,

    pub(crate) ext_asym: __IncompleteArrayField<__le32>,
    pub(crate) ext_hash: __IncompleteArrayField<__le32>,
    pub(crate) resp_alg_struct: __IncompleteArrayField<RegAlg>,
}

impl Default for NegotiateAlgsReq {
    fn default() -> Self {
        NegotiateAlgsReq {
            version: 0,
            code: SPDM_NEGOTIATE_ALGS,
            param1: 0, // Size of resp_alg_struct
            param2: 0,
            length: 32,
            measurement_specification: SPDM_MEAS_SPEC_DMTF,
            other_params_support: 0,
            base_asym_algo: SPDM_ASYM_ALGOS.to_le(),
            base_hash_algo: SPDM_HASH_ALGOS.to_le(),
            reserved1: [0u8; 12],
            ext_asym_count: 0,
            ext_hash_count: 0,
            reserved2: 0,
            mel_specification: 0,
            ext_asym: __IncompleteArrayField::new(),
            ext_hash: __IncompleteArrayField::new(),
            resp_alg_struct: __IncompleteArrayField::new(),
        }
    }
}

#[repr(C, packed)]
pub(crate) struct NegotiateAlgsRsp {
    pub(crate) version: u8,
    pub(crate) code: u8,
    pub(crate) param1: u8,
    pub(crate) param2: u8,

    pub(crate) length: u16,
    pub(crate) measurement_specification_sel: u8,
    pub(crate) other_params_sel: u8,

    pub(crate) measurement_hash_algo: u32,
    pub(crate) base_asym_sel: u32,
    pub(crate) base_hash_sel: u32,

    reserved1: [u8; 11],

    pub(crate) mel_specification_sel: u8,
    pub(crate) ext_asym_sel_count: u8,
    pub(crate) ext_hash_sel_count: u8,
    reserved2: [u8; 2],

    pub(crate) ext_asym: __IncompleteArrayField<__le32>,
    pub(crate) ext_hash: __IncompleteArrayField<__le32>,
    pub(crate) resp_alg_struct: __IncompleteArrayField<RegAlg>,
}

impl<'a> Validate<Untrusted<&'a [u8]>> for &'a NegotiateAlgsRsp {
    type Err = Error;

    fn validate(unvalidated: &[u8]) -> Result<Self, Self::Err> {
        if unvalidated.len() < mem::size_of::<NegotiateAlgsRsp>() {
            return Err(EINVAL);
        }

        let ptr = unvalidated.as_ptr();
        // CAST: `NegotiateAlgsRsp` only contains integers and has `repr(C)`.
        let ptr = ptr.cast::<NegotiateAlgsRsp>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        let rsp: &NegotiateAlgsRsp = unsafe { &*ptr };

        Ok(rsp)
    }
}

#[repr(C, packed)]
pub(crate) struct GetDigestsReq {
    pub(crate) version: u8,
    pub(crate) code: u8,
    pub(crate) param1: u8,
    pub(crate) param2: u8,
}

impl Default for GetDigestsReq {
    fn default() -> Self {
        GetDigestsReq {
            version: 0,
            code: SPDM_GET_DIGESTS,
            param1: 0,
            param2: 0,
        }
    }
}

#[repr(C, packed)]
pub(crate) struct GetDigestsRsp {
    pub(crate) version: u8,
    pub(crate) code: u8,
    pub(crate) param1: u8,
    pub(crate) param2: u8,

    pub(crate) digests: __IncompleteArrayField<u8>,
    // KeyPairIDs, added in 1.3

    // CertificateInfo, added in 1.3

    // KeyUsageMask, added in 1.3
}

impl<'a> Validate<Untrusted<&'a [u8]>> for &'a GetDigestsRsp {
    type Err = Error;

    fn validate(unvalidated: &[u8]) -> Result<Self, Self::Err> {
        if unvalidated.len() < mem::size_of::<GetDigestsRsp>() {
            return Err(EINVAL);
        }

        let ptr = unvalidated.as_ptr();
        // CAST: `GetDigestsRsp` only contains integers and has `repr(C)`.
        let ptr = ptr.cast::<GetDigestsRsp>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        let rsp: &GetDigestsRsp = unsafe { &*ptr };

        Ok(rsp)
    }
}
