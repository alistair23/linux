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
use kernel::prelude::*;
use kernel::{
    error::Error,
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

impl SpdmHeader {
    #[expect(dead_code)]
    pub(crate) fn new(code: u8) -> Self {
        SpdmHeader {
            version: 0,
            code,
            param1: 0,
            param2: 0,
        }
    }

    #[expect(dead_code)]
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
