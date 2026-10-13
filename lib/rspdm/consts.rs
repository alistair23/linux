// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Western Digital

//! Constants used by the library
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use crate::validator::SpdmHeader;
use core::mem;
use kernel::bits::{
    bit_u32,
    bit_u8, //
};

// SPDM versions supported by this implementation
pub(crate) const SPDM_VER_10: u8 = 0x10;
pub(crate) const SPDM_VER_11: u8 = 0x11;
pub(crate) const SPDM_VER_12: u8 = 0x12;
#[expect(dead_code)]
pub(crate) const SPDM_VER_13: u8 = 0x13;
pub(crate) const SPDM_VER_14: u8 = 0x14;

pub(crate) const SPDM_MIN_VER: u8 = SPDM_VER_10;
pub(crate) const SPDM_MAX_VER: u8 = SPDM_VER_14;

pub(crate) const SPDM_REQ: u8 = 0x80;
pub(crate) const SPDM_ERROR: u8 = 0x7f;

pub(crate) const SPDM_GET_VERSION: u8 = 0x84;
pub(crate) const SPDM_GET_VERSION_LEN: usize =
    mem::size_of::<SpdmHeader>() + 2 + (u8::MAX as usize) * mem::size_of::<u16>();

pub(crate) const SPDM_GET_CAPABILITIES: u8 = 0xe1;
pub(crate) const SPDM_CAP_SUPPORTED_ALGORITHMS: u8 = bit_u8(0);
pub(crate) const SPDM_MIN_DATA_TRANSFER_SIZE: u32 = 42; // SPDM 1.2.0 margin no 226

// SPDM cryptographic timeout of this implementation:
// Assume calculations may take up to 1 sec on a busy machine, which equals
// roughly 1 << 20.  That's within the limits mandated for responders by CMA
// (1 << 23 usec, PCIe r6.2 sec 6.31.3) and DOE (1 sec, PCIe r6.2 sec 6.30.2).
// Used in GET_CAPABILITIES exchange.
pub(crate) const SPDM_CTEXPONENT: u8 = 20;

pub(crate) const SPDM_CERT_CAP: u32 = bit_u32(1);
pub(crate) const SPDM_CHAL_CAP: u32 = bit_u32(2);

pub(crate) const SPDM_REQ_CAPS: u32 = SPDM_CERT_CAP | SPDM_CHAL_CAP;
pub(crate) const SPDM_RSP_MIN_CAPS: u32 = SPDM_CERT_CAP | SPDM_CHAL_CAP;
