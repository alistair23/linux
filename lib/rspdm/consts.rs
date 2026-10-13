// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Western Digital

//! Constants used by the library
//!
//! Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
//! <https://www.dmtf.org/dsp/DSP0274>

// SPDM versions supported by this implementation
pub(crate) const SPDM_VER_10: u8 = 0x10;

pub(crate) const SPDM_MIN_VER: u8 = SPDM_VER_10;

#[allow(dead_code)]
pub(crate) const SPDM_REQ: u8 = 0x80;
#[allow(dead_code)]
pub(crate) const SPDM_ERROR: u8 = 0x7f;
