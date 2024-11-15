// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Western Digital

//! Related structs and their Validate implementations.
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use crate::{
    consts::SpdmErrorCode,
    SpdmState, //
};
use core::mem;
use kernel::prelude::*;
use kernel::{
    error::Error,
    validate::{
        Untrusted,
        Validate, //
    },
};

use crate::consts::{
    SPDM_ASYM_ALGOS,
    SPDM_CAP_SUPPORTED_ALGORITHMS,
    SPDM_CTEXPONENT,
    SPDM_GET_CAPABILITIES,
    SPDM_GET_VERSION,
    SPDM_HASH_ALGOS,
    SPDM_MEAS_SPEC_DMTF,
    SPDM_MIN_DATA_TRANSFER_SIZE,
    SPDM_MIN_VER,
    SPDM_NEGOTIATE_ALGS,
    SPDM_REQ_CAPS,
    SPDM_VER_10,
    SPDM_VER_11,
    SPDM_VER_12, //
};

#[repr(C, packed)]
pub(crate) struct SpdmHeader {
    pub(crate) version: u8,
    pub(crate) code: u8, /* RequestResponseCode */
    pub(crate) param1: u8,
    pub(crate) param2: u8,
}

impl SpdmHeader {
    pub(crate) fn new(code: u8) -> Self {
        SpdmHeader {
            version: 0,
            code,
            param1: 0,
            param2: 0,
        }
    }

    pub(crate) fn to_bytes(&self) -> Result<KVec<u8>> {
        let mut out = KVec::new();

        out.extend_from_slice(
            &[self.version, self.code, self.param1, self.param2],
            GFP_KERNEL,
        )?;

        Ok(out)
    }
}

impl<'a, 'c> Validate<'c, Untrusted<&'a [u8]>> for SpdmHeader {
    type Err = Error;

    type Context = &'c SpdmState<'c>;

    fn validate(unvalidated: &[u8], _context: &'c SpdmState<'c>) -> Result<Self, Self::Err> {
        Ok(SpdmHeader {
            version: *unvalidated.get(0).ok_or(EIO)?,
            code: *unvalidated.get(1).ok_or(EIO)?,
            param1: *unvalidated.get(2).ok_or(EIO)?,
            param2: *unvalidated.get(3).ok_or(EIO)?,
        })
    }
}

#[expect(dead_code)]
pub(crate) struct SpdmErrorRsp {
    pub(crate) version: u8,
    /// This will always be SPDM_ERROR (0x7F)
    pub(crate) code: u8,
    pub(crate) error_code: SpdmErrorCode,
    pub(crate) error_data: u8,
}

impl<'a, 'c> Validate<'c, Untrusted<&'a [u8]>> for SpdmErrorRsp {
    type Err = Error;

    type Context = &'c SpdmState<'c>;

    fn validate(unvalidated: &[u8], _context: &'c SpdmState<'c>) -> Result<Self, Self::Err> {
        Ok(SpdmErrorRsp {
            version: *unvalidated.get(0).ok_or(EIO)?,
            code: *unvalidated.get(1).ok_or(EIO)?,
            // `try_from` rejects unknown `SpdmErrorCode` discriminants.
            error_code: SpdmErrorCode::try_from(*unvalidated.get(2).ok_or(EIO)?)?,
            error_data: *unvalidated.get(3).ok_or(EIO)?,
        })
    }
}

pub(crate) struct GetVersionReq {
    pub(crate) header: SpdmHeader,
}

impl GetVersionReq {
    pub(crate) fn to_bytes(&self) -> Result<KVec<u8>> {
        self.header.to_bytes()
    }
}

impl Default for GetVersionReq {
    fn default() -> Self {
        GetVersionReq {
            header: SpdmHeader::new(SPDM_GET_VERSION),
        }
    }
}

#[expect(dead_code)]
pub(crate) struct GetVersionRsp {
    pub(crate) header: SpdmHeader,

    pub(crate) version_number_entry_count: u8,
    pub(crate) version_number_entries: KVec<u16>,

    /// Size of the response, not public
    length: usize,
}

impl GetVersionRsp {
    #[expect(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.length
    }
}

impl<'a, 'c> Validate<'c, Untrusted<&'a [u8]>> for GetVersionRsp {
    type Err = Error;

    type Context = &'c SpdmState<'c>;

    fn validate(unvalidated: &[u8], context: &'c SpdmState<'c>) -> Result<Self, Self::Err> {
        let header: SpdmHeader =
            Untrusted::new(unvalidated.get(0..4).ok_or(EIO)?).validate(context)?;

        if header.code != SPDM_GET_VERSION - 0x80 {
            return Err(EINVAL);
        }

        if header.version != SPDM_MIN_VER {
            return Err(EINVAL);
        }

        let version_number_entry_count = *unvalidated.get(5).ok_or(EIO)?;

        // Entries follow header (4) + reserved (1) + count (1) = 6 bytes.
        let mut offset = mem::size_of::<SpdmHeader>() + 2;

        let mut version_number_entries = KVec::new();
        for _ in 0..version_number_entry_count {
            let entry = u16::from_le_bytes(
                unvalidated
                    .get(offset..offset + mem::size_of::<u16>())
                    .ok_or(EIO)?
                    .try_into()
                    .map_err(|_| EINVAL)?,
            );
            version_number_entries.push(entry, GFP_KERNEL)?;
            offset += mem::size_of::<u16>();
        }

        Ok(GetVersionRsp {
            header,
            version_number_entry_count,
            version_number_entries,
            length: offset,
        })
    }
}

pub(crate) struct GetCapabilitiesReq {
    pub(crate) header: SpdmHeader,

    pub(crate) ctexponent: u8,

    pub(crate) flags: u32,

    /* End of SPDM 1.1 structure */
    pub(crate) data_transfer_size: u32,
    pub(crate) max_spdm_msg_size: u32,
}

impl GetCapabilitiesReq {
    pub(crate) fn to_bytes(&self) -> Result<KVec<u8>> {
        let mut out = self.header.to_bytes()?;

        if self.header.version <= SPDM_VER_10 {
            return Ok(out);
        }

        out.push(0u8, GFP_KERNEL)?;
        out.push(self.ctexponent, GFP_KERNEL)?;

        out.extend_from_slice(&[0u8; 2], GFP_KERNEL)?;
        out.extend_from_slice(&self.flags.to_le_bytes(), GFP_KERNEL)?;

        if self.header.version >= SPDM_VER_12 {
            out.extend_from_slice(&self.data_transfer_size.to_le_bytes(), GFP_KERNEL)?;
            out.extend_from_slice(&self.max_spdm_msg_size.to_le_bytes(), GFP_KERNEL)?;
        }

        Ok(out)
    }
}

impl Default for GetCapabilitiesReq {
    fn default() -> Self {
        GetCapabilitiesReq {
            header: SpdmHeader::new(SPDM_GET_CAPABILITIES),

            ctexponent: SPDM_CTEXPONENT,
            flags: SPDM_REQ_CAPS,
            data_transfer_size: 0,
            max_spdm_msg_size: 0,
        }
    }
}

/// Response AlgStructure field format
#[expect(dead_code)]
pub(crate) struct RespAlgStruct {
    pub(crate) alg_type: u8,
    pub(crate) alg_count: u8,
    pub(crate) alg_supported: KVec<u8>,
    pub(crate) alg_external: KVec<u32>,
}

pub(crate) const GET_CAPABILITIES_RSP_SZ: usize = mem::size_of::<SpdmHeader>() + 16;

/// The GET_CAPABILITIES SupportedAlgorithms block (SPDM 1.3+).
///
/// Conforms to the NEGOTIATE_ALGORITHMS request message format,
/// including all fields from Param1 through the end of the message inclusive.
/// The `Length` field is equal to the total size of the block (`AlgSize`).
#[expect(dead_code)]
pub(crate) struct SupportedAlgorithms {
    /// param1
    pub(crate) alg_struct_count: u8,
    pub(crate) length: u16,

    pub(crate) measurement_specification: u8,
    pub(crate) other_params_support: u8,

    pub(crate) base_asym_algo: u32,
    pub(crate) base_hash_algo: u32,

    pub(crate) ext_asym_count: u8,
    pub(crate) ext_hash_count: u8,

    pub(crate) mel_specification: u8,

    pub(crate) ext_asym: KVec<u32>,
    pub(crate) ext_hash: KVec<u32>,
    pub(crate) alg_struct: KVec<RespAlgStruct>,
}

impl SupportedAlgorithms {
    fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        let read_le16 = |off: usize| -> Result<u16, Error> {
            Ok(u16::from_le_bytes(
                buf.get(off..off + mem::size_of::<u16>())
                    .ok_or(EIO)?
                    .try_into()
                    .map_err(|_| EINVAL)?,
            ))
        };
        let read_le32 = |off: usize| -> Result<u32, Error> {
            Ok(u32::from_le_bytes(
                buf.get(off..off + mem::size_of::<u32>())
                    .ok_or(EIO)?
                    .try_into()
                    .map_err(|_| EINVAL)?,
            ))
        };

        let alg_struct_count = *buf.get(0).ok_or(EIO)?;
        let length = read_le16(2)?;
        let measurement_specification = *buf.get(4).ok_or(EIO)?;
        let other_params_support = *buf.get(5).ok_or(EIO)?;
        let base_asym_algo = read_le32(6)?;
        let base_hash_algo = read_le32(10)?;
        let ext_asym_count = *buf.get(26).ok_or(EIO)?;
        let ext_hash_count = *buf.get(27).ok_or(EIO)?;
        let mel_specification = *buf.get(29).ok_or(EIO)?;

        let mut offset = 30;

        let mut ext_asym = KVec::new();
        for _ in 0..ext_asym_count {
            ext_asym.push(read_le32(offset)?, GFP_KERNEL)?;
            offset += mem::size_of::<u32>();
        }

        let mut ext_hash = KVec::new();
        for _ in 0..ext_hash_count {
            ext_hash.push(read_le32(offset)?, GFP_KERNEL)?;
            offset += mem::size_of::<u32>();
        }

        let mut alg_struct = KVec::new();
        for _ in 0..alg_struct_count {
            let alg_type = *buf.get(offset).ok_or(EIO)?;
            let alg_count = *buf.get(offset + 1).ok_or(EIO)?;

            let fixed_alg_count = (alg_count & 0xf) as usize;
            let ext_alg_count = (alg_count >> 4) as usize;

            offset += 2;

            let mut alg_supported = KVec::new();
            alg_supported.extend_from_slice(
                buf.get(offset..offset + fixed_alg_count).ok_or(EIO)?,
                GFP_KERNEL,
            )?;
            offset += fixed_alg_count;

            let mut alg_external = KVec::new();
            for _ in 0..ext_alg_count {
                alg_external.push(read_le32(offset)?, GFP_KERNEL)?;
                offset += mem::size_of::<u32>();
            }

            alg_struct.push(
                RespAlgStruct {
                    alg_type,
                    alg_count,
                    alg_supported,
                    alg_external,
                },
                GFP_KERNEL,
            )?;
        }

        if length as usize != offset {
            pr_err!("Malformed SupportedAlgorithms block\n");
            return Err(EPROTO);
        }

        Ok(SupportedAlgorithms {
            alg_struct_count,
            length,
            measurement_specification,
            other_params_support,
            base_asym_algo,
            base_hash_algo,
            ext_asym_count,
            ext_hash_count,
            mel_specification,
            ext_asym,
            ext_hash,
            alg_struct,
        })
    }
}

#[expect(dead_code)]
pub(crate) struct GetCapabilitiesRsp {
    pub(crate) header: SpdmHeader,

    pub(crate) ctexponent: u8,
    pub(crate) flags: u32,

    // End of SPDM 1.1 structure
    pub(crate) data_transfer_size: u32,
    pub(crate) max_spdm_msg_size: u32,

    pub(crate) supported_algorithms: Option<SupportedAlgorithms>,

    /// Size of the response, not public
    length: usize,
}

impl GetCapabilitiesRsp {
    #[expect(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.length
    }
}

impl<'a, 'c> Validate<'c, Untrusted<&'a [u8]>> for GetCapabilitiesRsp {
    type Err = Error;

    type Context = &'c SpdmState<'c>;

    fn validate(unvalidated: &[u8], context: &'c SpdmState<'c>) -> Result<Self, Self::Err> {
        let header: SpdmHeader =
            Untrusted::new(unvalidated.get(0..4).ok_or(EIO)?).validate(context)?;

        if header.code != SPDM_GET_CAPABILITIES - 0x80 {
            return Err(EINVAL);
        }

        if header.version != context.version {
            pr_err!("Invalid version response\n");
            return Err(EPROTO);
        }

        let ctexponent = *unvalidated.get(5).ok_or(EIO)?;
        let flags = u32::from_le_bytes(
            unvalidated
                .get(8..12)
                .ok_or(EIO)?
                .try_into()
                .map_err(|_| EINVAL)?,
        );

        // DataTransferSize and MaxSPDMmsgSize only exist in SPDM 1.2 and later.
        let (data_transfer_size, max_spdm_msg_size, supported_algorithms, length) =
            if context.version <= SPDM_VER_11 {
                (
                    0,
                    0,
                    None,
                    mem::size_of::<SpdmHeader>() + 4 + mem::size_of::<u32>(),
                )
            } else {
                let data_transfer_size = u32::from_le_bytes(
                    unvalidated
                        .get(12..16)
                        .ok_or(EIO)?
                        .try_into()
                        .map_err(|_| EINVAL)?,
                );
                let max_spdm_msg_size = u32::from_le_bytes(
                    unvalidated
                        .get(16..20)
                        .ok_or(EIO)?
                        .try_into()
                        .map_err(|_| EINVAL)?,
                );

                if data_transfer_size < SPDM_MIN_DATA_TRANSFER_SIZE {
                    pr_err!("Malformed capabilities response\n");
                    return Err(EPROTO);
                }

                let supported_algorithms = if header.param1 & SPDM_CAP_SUPPORTED_ALGORITHMS != 0 {
                    Some(SupportedAlgorithms::from_bytes(
                        unvalidated.get(GET_CAPABILITIES_RSP_SZ..).ok_or(EIO)?,
                    )?)
                } else {
                    None
                };

                let length = GET_CAPABILITIES_RSP_SZ
                    + supported_algorithms
                        .as_ref()
                        .map_or(0, |s| s.length as usize);

                (
                    data_transfer_size,
                    max_spdm_msg_size,
                    supported_algorithms,
                    length,
                )
            };

        Ok(GetCapabilitiesRsp {
            header,
            ctexponent,
            flags,
            data_transfer_size,
            max_spdm_msg_size,
            supported_algorithms,
            length,
        })
    }
}

pub(crate) struct NegotiateAlgsReq {
    pub(crate) header: SpdmHeader,

    pub(crate) length: u16,
    pub(crate) measurement_specification: u8,
    pub(crate) other_params_support: u8,

    pub(crate) base_asym_algo: u32,
    pub(crate) base_hash_algo: u32,

    pub(crate) ext_asym_count: u8,
    pub(crate) ext_hash_count: u8,
    pub(crate) mel_specification: u8,
    // ext_asym
    // ext_hash
    // resp_alg_struct
}

impl NegotiateAlgsReq {
    pub(crate) const WIRE_SIZE: usize = mem::size_of::<SpdmHeader>() + 28;

    pub(crate) fn to_bytes(&self) -> Result<KVec<u8>> {
        let mut out = self.header.to_bytes()?;

        out.extend_from_slice(&self.length.to_le_bytes(), GFP_KERNEL)?;
        out.push(self.measurement_specification, GFP_KERNEL)?;
        out.push(self.other_params_support, GFP_KERNEL)?;

        out.extend_from_slice(&self.base_asym_algo.to_le_bytes(), GFP_KERNEL)?;
        out.extend_from_slice(&self.base_hash_algo.to_le_bytes(), GFP_KERNEL)?;

        out.extend_from_slice(&[0u8; 12], GFP_KERNEL)?;

        out.push(self.ext_asym_count, GFP_KERNEL)?;
        out.push(self.ext_hash_count, GFP_KERNEL)?;
        out.push(0u8, GFP_KERNEL)?;
        out.push(self.mel_specification, GFP_KERNEL)?;

        Ok(out)
    }
}

impl Default for NegotiateAlgsReq {
    fn default() -> Self {
        NegotiateAlgsReq {
            header: SpdmHeader::new(SPDM_NEGOTIATE_ALGS),

            length: 32,
            measurement_specification: SPDM_MEAS_SPEC_DMTF,
            other_params_support: 0,
            base_asym_algo: SPDM_ASYM_ALGOS,
            base_hash_algo: SPDM_HASH_ALGOS,
            ext_asym_count: 0,
            ext_hash_count: 0,
            mel_specification: 0,
        }
    }
}

/// Size of  everything up to the variable-length algorithm arrays (ExtAsymSel).
pub(crate) const NEGOTIATE_ALGS_RSP_SZ: usize = mem::size_of::<SpdmHeader>() + 32;

#[expect(dead_code)]
pub(crate) struct NegotiateAlgsRsp {
    pub(crate) header: SpdmHeader,

    pub(crate) measurement_specification_sel: u8,
    pub(crate) other_params_sel: u8,

    pub(crate) measurement_hash_algo: u32,
    pub(crate) base_asym_sel: u32,
    pub(crate) base_hash_sel: u32,

    pub(crate) mel_specification_sel: u8,
    pub(crate) ext_asym_sel_count: u8,
    pub(crate) ext_hash_sel_count: u8,

    pub(crate) ext_asym: KVec<u32>,
    pub(crate) ext_hash: KVec<u32>,
    pub(crate) resp_alg_struct: KVec<RespAlgStruct>,

    /// Size of the response, not public
    length: usize,
}

impl NegotiateAlgsRsp {
    #[expect(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.length
    }
}

impl<'a, 'c> Validate<'c, Untrusted<&'a [u8]>> for NegotiateAlgsRsp {
    type Err = Error;

    type Context = &'c SpdmState<'c>;

    fn validate(unvalidated: &[u8], context: &'c SpdmState<'c>) -> Result<Self, Self::Err> {
        let header: SpdmHeader =
            Untrusted::new(unvalidated.get(0..4).ok_or(EIO)?).validate(context)?;

        if header.code != SPDM_NEGOTIATE_ALGS - 0x80 {
            return Err(EINVAL);
        }

        if header.version != context.version {
            pr_err!("Invalid version response\n");
            return Err(EPROTO);
        }

        let resp_len = u16::from_le_bytes(
            unvalidated
                .get(4..4 + mem::size_of::<u16>())
                .ok_or(EIO)?
                .try_into()
                .map_err(|_| EINVAL)?,
        );

        let measurement_specification_sel = *unvalidated.get(6).ok_or(EIO)?;
        let other_params_sel = *unvalidated.get(7).ok_or(EIO)?;

        // Helper to read a little-endian `u32`
        let read_le32 = |offset: usize| -> Result<u32, Error> {
            Ok(u32::from_le_bytes(
                unvalidated
                    .get(offset..offset + mem::size_of::<u32>())
                    .ok_or(EIO)?
                    .try_into()
                    .map_err(|_| EINVAL)?,
            ))
        };

        let measurement_hash_algo = read_le32(8)?;
        let base_asym_sel = read_le32(12)?;
        let base_hash_sel = read_le32(16)?;

        let mel_specification_sel = *unvalidated.get(31).ok_or(EIO)?;
        let ext_asym_sel_count = *unvalidated.get(32).ok_or(EIO)?;
        let ext_hash_sel_count = *unvalidated.get(33).ok_or(EIO)?;

        let mut offset = NEGOTIATE_ALGS_RSP_SZ;

        let mut ext_asym = KVec::new();
        for _ in 0..ext_asym_sel_count {
            ext_asym.push(read_le32(offset)?, GFP_KERNEL)?;
            offset += mem::size_of::<u32>();
        }

        let mut ext_hash = KVec::new();
        for _ in 0..ext_hash_sel_count {
            ext_hash.push(read_le32(offset)?, GFP_KERNEL)?;
            offset += mem::size_of::<u32>();
        }

        let mut resp_alg_struct = KVec::new();
        for _ in 0..header.param1 {
            let alg_type = *unvalidated.get(offset).ok_or(EIO)?;
            let alg_count = *unvalidated.get(offset + 1).ok_or(EIO)?;
            let fixed_alg_count = (alg_count & 0xf) as usize;
            let ext_alg_count = (alg_count >> 4) as usize;
            offset += 2;

            let mut alg_supported = KVec::new();
            alg_supported.extend_from_slice(
                unvalidated
                    .get(offset..offset + fixed_alg_count)
                    .ok_or(EIO)?,
                GFP_KERNEL,
            )?;
            offset += fixed_alg_count;

            let mut alg_external = KVec::new();
            for _ in 0..ext_alg_count {
                alg_external.push(read_le32(offset)?, GFP_KERNEL)?;
                offset += mem::size_of::<u32>();
            }

            resp_alg_struct.push(
                RespAlgStruct {
                    alg_type,
                    alg_count,
                    alg_supported,
                    alg_external,
                },
                GFP_KERNEL,
            )?;
        }

        if resp_len != offset as u16 {
            pr_err!("Incorrect response length reported\n");
            return Err(EPROTO);
        }

        Ok(NegotiateAlgsRsp {
            header,
            measurement_specification_sel,
            other_params_sel,
            measurement_hash_algo,
            base_asym_sel,
            base_hash_sel,
            mel_specification_sel,
            ext_asym_sel_count,
            ext_hash_sel_count,
            ext_asym,
            ext_hash,
            resp_alg_struct,
            length: offset,
        })
    }
}
