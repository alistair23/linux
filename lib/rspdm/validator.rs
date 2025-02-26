// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Western Digital

//! Related structs and their Validate implementations.
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use crate::bindings::{__IncompleteArrayField, __le16, __le32};
use crate::consts::SpdmErrorCode;
use core::mem;
use kernel::prelude::*;
use kernel::{
    error::{code::EINVAL, Error},
    validate::{Unvalidated, Validate},
};

use crate::consts::{
    SPDM_ASYM_ALGOS, SPDM_CHALLENGE, SPDM_CTEXPONENT, SPDM_GET_CAPABILITIES, SPDM_GET_CERTIFICATE,
    SPDM_GET_DIGESTS, SPDM_GET_VERSION, SPDM_HASH_ALGOS, SPDM_MEAS_SPEC_DMTF, SPDM_NEGOTIATE_ALGS,
    SPDM_REQ_CAPS,
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

#[repr(C, packed)]
pub(crate) struct GetCapabilitiesReq {
    pub(crate) version: u8,
    pub(crate) code: u8,
    pub(crate) param1: u8,
    pub(crate) param2: u8,

    reserved1: u8,
    pub(crate) ctexponent: u8,
    reserved2: u16,

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
            reserved2: 0,
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
    pub(crate) param2: u8,

    reserved1: u8,
    pub(crate) ctexponent: u8,
    reserved2: u16,

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
            return Err(EINVAL);
        }

        let ptr = raw.as_mut_ptr();
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
    pub(crate) param1: u8,
    pub(crate) param2: u8,

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
    pub(crate) req_alg_struct: __IncompleteArrayField<RegAlg>,
}

impl Default for NegotiateAlgsReq {
    fn default() -> Self {
        NegotiateAlgsReq {
            version: 0,
            code: SPDM_NEGOTIATE_ALGS,
            param1: 0,
            param2: 0,
            length: 0,
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
            req_alg_struct: __IncompleteArrayField::new(),
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
    pub(crate) req_alg_struct: __IncompleteArrayField<RegAlg>,
}

impl Validate<&mut Unvalidated<KVec<u8>>> for &mut NegotiateAlgsRsp {
    type Err = Error;

    fn validate(unvalidated: &mut Unvalidated<KVec<u8>>) -> Result<Self, Self::Err> {
        let raw = unvalidated.raw_mut();
        if raw.len() < mem::size_of::<NegotiateAlgsRsp>() {
            return Err(EINVAL);
        }

        let ptr = raw.as_mut_ptr();
        // CAST: `NegotiateAlgsRsp` only contains integers and has `repr(C)`.
        let ptr = ptr.cast::<NegotiateAlgsRsp>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        let rsp: &mut NegotiateAlgsRsp = unsafe { &mut *ptr };

        rsp.base_asym_sel = rsp.base_asym_sel.to_le();
        rsp.base_hash_sel = rsp.base_hash_sel.to_le();
        rsp.measurement_hash_algo = rsp.measurement_hash_algo.to_le();

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
}

impl Validate<&mut Unvalidated<KVec<u8>>> for &mut GetDigestsRsp {
    type Err = Error;

    fn validate(unvalidated: &mut Unvalidated<KVec<u8>>) -> Result<Self, Self::Err> {
        let raw = unvalidated.raw_mut();
        if raw.len() < mem::size_of::<GetDigestsRsp>() {
            return Err(EINVAL);
        }

        let ptr = raw.as_mut_ptr();
        // CAST: `GetDigestsRsp` only contains integers and has `repr(C)`.
        let ptr = ptr.cast::<GetDigestsRsp>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        let rsp: &mut GetDigestsRsp = unsafe { &mut *ptr };

        Ok(rsp)
    }
}

#[repr(C, packed)]
pub(crate) struct GetCertificateReq {
    pub(crate) version: u8,
    pub(crate) code: u8,
    pub(crate) param1: u8,
    pub(crate) param2: u8,

    pub(crate) offset: u16,
    pub(crate) length: u16,
}

impl Default for GetCertificateReq {
    fn default() -> Self {
        GetCertificateReq {
            version: 0,
            code: SPDM_GET_CERTIFICATE,
            param1: 0,
            param2: 0,
            offset: 0,
            length: 0,
        }
    }
}

#[repr(C, packed)]
pub(crate) struct GetCertificateRsp {
    pub(crate) version: u8,
    pub(crate) code: u8,
    pub(crate) param1: u8,
    pub(crate) param2: u8,

    pub(crate) portion_length: u16,
    pub(crate) remainder_length: u16,

    pub(crate) cert_chain: __IncompleteArrayField<u8>,
}

impl Validate<&mut Unvalidated<KVec<u8>>> for &mut GetCertificateRsp {
    type Err = Error;

    fn validate(unvalidated: &mut Unvalidated<KVec<u8>>) -> Result<Self, Self::Err> {
        let raw = unvalidated.raw_mut();
        if raw.len() < mem::size_of::<GetCertificateRsp>() {
            return Err(EINVAL);
        }

        let ptr = raw.as_mut_ptr();
        // CAST: `GetCertificateRsp` only contains integers and has `repr(C)`.
        let ptr = ptr.cast::<GetCertificateRsp>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        let rsp: &mut GetCertificateRsp = unsafe { &mut *ptr };

        rsp.portion_length = rsp.portion_length.to_le();
        rsp.remainder_length = rsp.remainder_length.to_le();

        Ok(rsp)
    }
}

#[repr(C, packed)]
pub(crate) struct ChallengeReq {
    pub(crate) version: u8,
    pub(crate) code: u8,
    pub(crate) param1: u8,
    pub(crate) param2: u8,

    pub(crate) nonce: [u8; 32],
    pub(crate) context: [u8; 8],
}

impl Default for ChallengeReq {
    fn default() -> Self {
        ChallengeReq {
            version: 0,
            code: SPDM_CHALLENGE,
            param1: 0,
            param2: 0,
            nonce: [0; 32],
            context: [0; 8],
        }
    }
}

#[repr(C, packed)]
pub(crate) struct ChallengeRsp {
    pub(crate) version: u8,
    pub(crate) code: u8,
    pub(crate) param1: u8,
    pub(crate) param2: u8,

    pub(crate) cert_chain_hash: __IncompleteArrayField<u8>,
    pub(crate) nonce: [u8; 32],
    pub(crate) message_summary_hash: __IncompleteArrayField<u8>,

    pub(crate) opaque_data_len: u16,
    pub(crate) opaque_data: __IncompleteArrayField<u8>,

    pub(crate) context: [u8; 8],
    pub(crate) signature: __IncompleteArrayField<u8>,
}

impl Validate<&mut Unvalidated<KVec<u8>>> for &mut ChallengeRsp {
    type Err = Error;

    fn validate(unvalidated: &mut Unvalidated<KVec<u8>>) -> Result<Self, Self::Err> {
        let raw = unvalidated.raw_mut();
        if raw.len() < mem::size_of::<ChallengeRsp>() {
            return Err(EINVAL);
        }

        let ptr = raw.as_mut_ptr();
        // CAST: `ChallengeRsp` only contains integers and has `repr(C)`.
        let ptr = ptr.cast::<ChallengeRsp>();
        // SAFETY: `ptr` came from a reference and the cast above is valid.
        let rsp: &mut ChallengeRsp = unsafe { &mut *ptr };

        // rsp.opaque_data_len = rsp.opaque_data_len.to_le();

        Ok(rsp)
    }
}
