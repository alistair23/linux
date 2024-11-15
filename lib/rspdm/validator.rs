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

    type Context = &'c SpdmState;

    fn validate(unvalidated: &[u8], _context: &'c SpdmState) -> Result<Self, Self::Err> {
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

    type Context = &'c SpdmState;

    fn validate(unvalidated: &[u8], _context: &'c SpdmState) -> Result<Self, Self::Err> {
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

    type Context = &'c SpdmState;

    fn validate(unvalidated: &[u8], context: &'c SpdmState) -> Result<Self, Self::Err> {
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
