// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Western Digital

//! Wrappers around the Linux kernel crypto public key APIs.
//!
//! C headers: [`include/crypto/public_key.h`](srctree/include/crypto/public_key.h).
//!
//! Reference: <https://www.kernel.org/doc/html/latest/crypto/asymmetric-keys.html>

use core::ptr::NonNull;
use kernel::prelude::*;
use kernel::{
    bindings,
    error::to_result, //
};

/// Owned `struct public_key` wrapper.
pub struct PublicKey {
    key: NonNull<bindings::public_key>,
}

impl PublicKey {
    /// Create a Rust `PublicKey` from a valid C `struct public_key` pointer.
    ///
    /// # Safety
    ///
    /// `key` must point to a valid, exclusively-owned `struct public_key`
    /// whose ownership is transferred to the returned `PublicKey`. The key
    /// is freed with `public_key_free()` when the `PublicKey` is dropped,
    /// so the caller must not free it itself or pass the same pointer to
    /// `from_raw()` again.
    #[inline]
    pub unsafe fn from_raw(key: NonNull<bindings::public_key>) -> Self {
        Self { key }
    }

    /// Verify a signature using this public key.
    #[inline]
    pub fn verify_signature(
        &self,
        signature: &[u8],
        encoding: &'static CStr,
        hash_algo: &'static CStr,
        message: &[u8],
    ) -> Result {
        // SAFETY: `self.key` is valid per the struct invariants; its
        // `pkey_algo` is populated by the key parser.
        let pkey_algo = unsafe { (*self.key.as_ptr()).pkey_algo };

        let sig = bindings::public_key_signature {
            pkey_algo,
            s: signature.as_ptr().cast_mut(),
            s_size: u32::try_from(signature.len()).map_err(|_| EINVAL)?,
            encoding: encoding.as_char_ptr().cast::<u8>(),
            hash_algo: hash_algo.as_char_ptr().cast::<u8>(),
            m: message.as_ptr().cast_mut(),
            m_size: u32::try_from(message.len()).map_err(|_| EINVAL)?,
            ..Default::default()
        };

        // SAFETY: `self.key` is a valid public key handle, and `sig` points to
        // valid signature/message data owned by the caller for the duration of
        // this call.
        unsafe {
            to_result(bindings::public_key_verify_signature(
                self.key.as_ptr(),
                &sig,
            ))
        }
    }
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        // SAFETY: `self.key` was either returned by `x509_cert_parse()` or
        // manually transferred from an `x509_certificate` and has not been
        // freed yet.
        unsafe {
            bindings::public_key_free(self.key.as_ptr());
        }
    }
}
