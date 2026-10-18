// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Western Digital

//! Wrappers around the Linux kernel crypto hash APIs.
//!
//! C headers: [`include/crypto/hash.h`](srctree/include/crypto/hash.h).
//!
//! Reference: <https://www.kernel.org/doc/html/latest/crypto/devel-algos.html#hashing-hash>

use core::ptr::NonNull;
use kernel::prelude::*;
use kernel::{
    bindings,
    error::{
        from_err_ptr,
        to_result, //
    },
    str::CStr,
};

/// Synchronous hash transformation plus its descriptor buffer.
pub struct Shash {
    shash: NonNull<bindings::crypto_shash>,
    desc: NonNull<bindings::shash_desc>,
    desc_len: usize,
    desc_capacity: usize,
    hash_len: usize,
    name: &'static CStr,
}

impl Shash {
    /// Allocates a hash transformation and initialises a descriptor for it.
    pub fn new(name: &'static CStr) -> Result<Self> {
        // SAFETY: `name.as_char_ptr()` is a valid NUL-terminated C string.
        // `crypto_alloc_shash()` returns a valid pointer or an ERR_PTR.
        let shash =
            from_err_ptr(unsafe { bindings::crypto_alloc_shash(name.as_char_ptr(), 0, 0) })?;
        let shash = NonNull::new(shash).ok_or(ENOMEM)?;

        // SAFETY: `shash` is a valid `crypto_shash` handle.
        let desc_size = unsafe { bindings::crypto_shash_descsize(shash.as_ptr()) } as usize;
        // SAFETY: `shash` is a valid `crypto_shash` handle.
        let hash_len = unsafe { bindings::crypto_shash_digestsize(shash.as_ptr()) } as usize;
        let desc_len = core::mem::size_of::<bindings::shash_desc>() + desc_size;

        let desc_vec = match KVec::from_elem(0u8, desc_len, GFP_KERNEL) {
            Ok(desc_vec) => desc_vec,
            Err(e) => {
                // SAFETY: `shash` was allocated above and must be freed if the
                // descriptor allocation fails.
                unsafe {
                    bindings::crypto_free_shash(shash.as_ptr());
                }
                return Err(e.into());
            }
        };

        let (desc_buf, _desc_len, desc_capacity) = desc_vec.into_raw_parts();
        let desc = NonNull::new(desc_buf.cast::<bindings::shash_desc>()).ok_or(ENOMEM)?;

        // SAFETY: `desc` points to an allocation of `desc_len` bytes, which is
        // exactly large enough for a `shash_desc` header and its trailing
        // algorithm state.
        unsafe {
            (*desc.as_ptr()).tfm = shash.as_ptr();
        }

        // SAFETY: `desc` is a valid `shash_desc` buffer with `tfm` initialised.
        if let Err(e) = unsafe { to_result(bindings::crypto_shash_init(desc.as_ptr())) } {
            // SAFETY: `desc.as_ptr()`, `desc_len`, and `desc_capacity` are the
            // exact parts returned by `into_raw_parts()` above.
            let desc_vec = unsafe {
                KVec::<u8>::from_raw_parts(desc.as_ptr().cast::<u8>(), desc_len, desc_capacity)
            };
            drop(desc_vec);

            // SAFETY: `shash` is a valid handle created above.
            unsafe {
                bindings::crypto_free_shash(shash.as_ptr());
            }
            return Err(e);
        }

        Ok(Self {
            shash,
            desc,
            desc_len,
            desc_capacity,
            hash_len,
            name,
        })
    }

    /// Return the name of the hash
    pub fn name(&self) -> &'static CStr {
        self.name
    }

    /// Return the name of the hash output
    pub fn hash_len(&self) -> usize {
        self.hash_len
    }

    /// Computes a one-shot digest into `out`, which must be exactly the digest
    /// size of the selected hash algorithm.
    pub fn digest(&self, data: &[u8], out: &mut [u8]) -> Result {
        if out.len() != self.hash_len {
            return Err(EINVAL);
        }

        // SAFETY: `self.desc` was created by `Shash::new()` and points to a
        // valid `shash_desc` with a valid `tfm`. `out` is checked above to be
        // exactly `crypto_shash_digestsize()` bytes.
        unsafe {
            to_result(bindings::crypto_shash_digest(
                self.desc.as_ptr(),
                data.as_ptr(),
                data.len() as u32,
                out.as_mut_ptr(),
            ))
        }
    }
}

impl Drop for Shash {
    fn drop(&mut self) {
        // SAFETY: `self.desc` was produced from a `KVec<u8>` allocation by
        // `into_raw_parts()` in `Shash::new()`, and `desc_len` and
        // `desc_capacity` are the exact values handed out at that time.
        let desc_vec = unsafe {
            KVec::<u8>::from_raw_parts(
                self.desc.as_ptr().cast::<u8>(),
                self.desc_len,
                self.desc_capacity,
            )
        };
        drop(desc_vec);

        // SAFETY: `self.shash` is a valid handle created by `crypto_alloc_shash()`.
        unsafe {
            bindings::crypto_free_shash(self.shash.as_ptr());
        }
    }
}
