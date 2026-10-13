// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Western Digital

//! Constants used by the library
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

use crate::validator::SpdmHeader;
use core::mem;

// SPDM versions supported by this implementation
pub(crate) const SPDM_VER_10: u8 = 0x10;
#[expect(dead_code)]
pub(crate) const SPDM_VER_11: u8 = 0x11;
#[expect(dead_code)]
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
