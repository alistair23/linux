// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Western Digital

//! Wrappers around the Linux kernel X509 parser APIs.
//!
//! C headers: [`include/keys/x509-parser.h`](srctree/include/keys/x509-parser.h).

use core::ffi::c_void;
use core::ptr::{self, NonNull};
use kernel::prelude::*;
use kernel::{
    bindings,
    error::{
        from_err_ptr,
        to_result, //
    },
    public_key::PublicKey,
};

/// Owned `struct x509_certificate` wrapper.
pub struct Certificate {
    cert: NonNull<bindings::x509_certificate>,
}

impl Certificate {
    /// Parses a DER certificate from `data` and returns it with the length
    /// of the certificate in bytes.
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        // SAFETY: `data.as_ptr()` points to at least `data.len()` valid bytes.
        let len = unsafe { bindings::x509_get_certificate_length(data.as_ptr(), data.len()) };
        let len = usize::try_from(len).map_err(|_| {
            pr_err!("Invalid certificate length\n");
            EPROTO
        })?;

        if len > data.len() {
            pr_err!("Certificate length is larger then the buffer\n");
            return Err(EPROTO);
        }

        // SAFETY: `data.as_ptr()` points to `data.len()` valid bytes and the
        // caller has already checked that the DER certificate length fits in
        // that buffer.
        let cert = from_err_ptr(unsafe {
            bindings::x509_cert_parse(data.as_ptr().cast::<c_void>(), len)
        })?;
        let cert = NonNull::new(cert).ok_or(EINVAL)?;

        Ok((Self { cert }, len))
    }

    /// Returns the raw pointer for the X.509 certificate.
    /// This is what is returned from the C function x509_cert_parse()
    pub fn raw(&self) -> *mut bindings::x509_certificate {
        self.cert.as_ptr()
    }

    /// Check that the certificate is not unsupported or blacklisted.
    pub fn check_accepted(&self) -> Result {
        // SAFETY: `self.cert` was returned by `x509_cert_parse()` and remains
        // valid until dropped.
        let cert = unsafe { &*self.cert.as_ptr() };
        if cert.unsupported_sig || cert.blacklisted {
            pr_err!("Certificate was rejected\n");
            return Err(EKEYREJECTED);
        }

        Ok(())
    }

    /// Verify that `child`'s signature is signed by this cert's public/private key.
    pub fn verify_signed(&self, child: &Self) -> Result {
        // SAFETY: both certificate pointers were produced by `x509_cert_parse()`
        // and remain valid until dropped.
        let (prev, child) = unsafe { (&*self.cert.as_ptr(), &*child.cert.as_ptr()) };

        let prev_pub = NonNull::new(prev.pub_).ok_or(EINVAL)?;
        let child_sig = NonNull::new(child.sig).ok_or(EINVAL)?;

        // SAFETY: `prev_pub` and `child_sig` are valid for at least the duration
        // of this call.
        unsafe {
            to_result(bindings::public_key_verify_signature(
                prev_pub.as_ptr(),
                child_sig.as_ptr(),
            ))
        }
    }

    /// Transfers the public key out of the certificate so the certificate can be
    /// dropped without freeing the public key.
    pub fn take_public_key(&mut self) -> Option<PublicKey> {
        // SAFETY: `self.cert` is a valid certificate pointer.
        let raw = unsafe { (*self.cert.as_ptr()).pub_ };
        let key = NonNull::new(raw)?;

        // SAFETY: `self.cert` is a valid certificate pointer. Clearing `pub_`
        // transfers ownership of the public key to the returned `PublicKey`.
        // The `pub_` field will not be freed by `x509_free_certificate()` in
        // Drop
        unsafe {
            (*self.cert.as_ptr()).pub_ = ptr::null_mut();
        }

        Some(PublicKey::from_raw(key))
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        // SAFETY: `self.cert` was produced by `x509_cert_parse()` and has
        // not been freed yet.
        unsafe {
            bindings::x509_free_certificate(self.cert.as_ptr());
        }
    }
}
