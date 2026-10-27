// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Western Digital

//! Wrappers around the Linux kernel X509 parser APIs.
//!
//! C headers: [`include/keys/x509-parser.h`](srctree/include/keys/x509-parser.h).

use core::marker::PhantomData;
use core::ptr::{
    self,
    NonNull, //
};
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
pub struct Certificate<'a> {
    cert: NonNull<bindings::x509_certificate>,
    _data: PhantomData<&'a [u8]>,
}

/// Key extension flags of the certificate's public key (`key_eflags`
/// bits), as defined for `struct public_key` in
/// [`include/crypto/public_key.h`](srctree/include/crypto/public_key.h).
#[derive(Clone, Copy, Debug)]
pub struct KeyExtFlags(usize);

impl KeyExtFlags {
    /// Whether the CA basic constraint is asserted.
    pub fn is_ca(self) -> bool {
        self.0 & (1 << bindings::KEY_EFLAG_CA) != 0
    }

    /// Whether the keyCertSign key usage is asserted.
    pub fn key_cert_sign(self) -> bool {
        self.0 & (1 << bindings::KEY_EFLAG_KEYCERTSIGN) != 0
    }

    /// Whether the digitalSignature key usage is asserted.
    pub fn digital_signature(self) -> bool {
        self.0 & (1 << bindings::KEY_EFLAG_DIGITALSIG) != 0
    }
}

impl<'a> Certificate<'a> {
    /// Parses a DER certificate from `data` and returns it with the length
    /// of the certificate in bytes.
    ///
    /// The returned certificate borrows `data` (`x509_cert_parse()` keeps
    /// pointers into the DER buffer), so `data` must outlive it.
    pub fn parse(data: &'a [u8]) -> Result<(Self, usize)> {
        // SAFETY: `data.as_ptr()` points to at least `data.len()` valid bytes.
        let len = unsafe { bindings::x509_get_certificate_length(data.as_ptr(), data.len()) };
        let len = usize::try_from(len).map_err(|_| {
            pr_err!("Invalid certificate length\n");
            EPROTO
        })?;

        if len > data.len() {
            pr_err!("Certificate length is larger than the buffer\n");
            return Err(EPROTO);
        }

        // SAFETY: `data.as_ptr()` points to `data.len()` valid bytes and the
        // caller has already checked that the DER certificate length fits in
        // that buffer.
        let cert = from_err_ptr(unsafe {
            bindings::x509_cert_parse(data.as_ptr().cast::<c_void>(), len)
        })?;
        let cert = NonNull::new(cert).ok_or(EINVAL)?;

        Ok((
            Self {
                cert,
                _data: PhantomData,
            },
            len,
        ))
    }

    /// Returns the raw pointer for the X.509 certificate.
    /// This is what is returned from the C function x509_cert_parse()
    #[inline]
    pub fn as_raw(&self) -> *const bindings::x509_certificate {
        self.cert.as_ptr()
    }

    /// Raw issuer name of the certificate.
    #[inline]
    pub fn raw_issuer(&self) -> &'a [u8] {
        // SAFETY: `self.cert` is valid per the struct invariants, and the
        // parser borrows the `raw_issuer` slice from the input buffer, which
        // outlives `self` for the lifetime `'a`.
        unsafe {
            let cert = &*self.cert.as_ptr();
            if cert.raw_issuer.is_null() {
                return &[];
            }
            core::slice::from_raw_parts(cert.raw_issuer.cast::<u8>(), cert.raw_issuer_size as usize)
        }
    }

    /// Raw subject name of the certificate.
    #[inline]
    pub fn raw_subject(&self) -> &'a [u8] {
        // SAFETY: `self.cert` is valid per the struct invariants, and the
        // parser borrows the `raw_subject` slice from the input buffer, which
        // outlives `self` for the lifetime `'a`.
        unsafe {
            let cert = &*self.cert.as_ptr();
            if cert.raw_subject.is_null() {
                return &[];
            }
            core::slice::from_raw_parts(
                cert.raw_subject.cast::<u8>(),
                cert.raw_subject_size as usize,
            )
        }
    }

    /// Key extension flags of the certificate's public key.
    #[inline]
    pub fn key_ext_flags(&self) -> Result<KeyExtFlags> {
        // SAFETY: `self.cert` is valid per the struct invariants.
        let pub_key = unsafe { (*self.cert.as_ptr()).pub_ };
        let pub_key = NonNull::new(pub_key).ok_or(EINVAL)?;

        // SAFETY: `pub_key` is owned by `self.cert` and, as it was just
        // checked to be non-NULL, valid to read.
        Ok(KeyExtFlags(unsafe { (*pub_key.as_ptr()).key_eflags }))
    }

    /// Name of the public key algorithm (e.g. `"rsa"` or `"ecdsa"`).
    #[inline]
    pub fn pkey_algo(&self) -> Result<&'static CStr> {
        // SAFETY: `self.cert` is valid per the struct invariants.
        let pub_key = unsafe { (*self.cert.as_ptr()).pub_ };
        let pub_key = NonNull::new(pub_key).ok_or(EINVAL)?;

        // SAFETY: `pub_key` is valid and non-NULL as checked above;
        // `pkey_algo` points to static kernel algorithm-name strings for
        // keys created by the X.509 parser.
        let name = unsafe { (*pub_key.as_ptr()).pkey_algo };
        let name = NonNull::new(name.cast_mut()).ok_or(EINVAL)?;

        // SAFETY: `name` points to a NUL-terminated C string with static
        // lifetime, as established by the parser.
        Ok(unsafe { CStr::from_char_ptr(name.as_ptr()) })
    }

    /// Length of the raw public key (in bytes). For RSA keys this is the
    /// modulus length; for ECDSA keys the uncompressed public key encoding.
    #[inline]
    pub fn pkey_len(&self) -> Result<usize> {
        // SAFETY: `self.cert` is valid per the struct invariants.
        let pub_key = unsafe { (*self.cert.as_ptr()).pub_ };
        let pub_key = NonNull::new(pub_key).ok_or(EINVAL)?;

        // SAFETY: `pub_key` is valid and non-NULL as checked above.
        Ok(unsafe { (*pub_key.as_ptr()).keylen } as usize)
    }

    /// Check that the certificate is not unsupported or blacklisted.
    #[inline]
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
    #[inline]
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
    #[inline]
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

        // SAFETY: `key` was just extracted from `self.cert`, which no longer
        // owns it since `pub_` was cleared above, so ownership is transferred
        // to the `PublicKey` exclusively.
        Some(unsafe { PublicKey::from_raw(key) })
    }
}

impl Drop for Certificate<'_> {
    fn drop(&mut self) {
        // SAFETY: `self.cert` was produced by `x509_cert_parse()` and has
        // not been freed yet.
        unsafe {
            bindings::x509_free_certificate(self.cert.as_ptr());
        }
    }
}
