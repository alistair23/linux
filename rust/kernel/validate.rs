// SPDX-License-Identifier: GPL-2.0

//! Types for handling and validating untrusted data.
//!
//! # Overview
//!
//! Untrusted data is marked using the [`Untrusted<T>`] type. See [Rationale](#rationale) for the
//! reasons to mark untrusted data throught the kernel. It is a totally opaque wrapper, it is not
//! possible to read the data inside; but it is possible to [`Untrusted::write`] into it.
//!
//! The only way to "access" the data inside an [`Untrusted<T>`] is to [`Untrusted::validate`] it;
//! turning it into a different form using the [`Validate`] trait. That trait receives the data in
//! the form of [`Unvalidated<T>`], which in contrast to [`Untrusted<T>`], allows access to the
//! underlying data. It additionally provides several utility functions to simplify validation.
//!
//! # Rationale
//!
//! When reading data from an untrusted source, it must be validated before it can be used for
//! logic. For example, this is a very bad idea:
//!
//! ```
//! # fn read_bytes_from_network() -> Box<[u8]> {
//! #     Box::new([1, 0], kernel::alloc::flags::GFP_KERNEL).unwrap()
//! # }
//! let bytes: Box<[u8]> = read_bytes_from_network();
//! let data_index = bytes[0];
//! let data = bytes[usize::from(data_index)];
//! ```
//!
//! While this will not lead to a memory violation (because the array index checks the bounds), it
//! might result in a kernel panic. For this reason, all untrusted data must be wrapped in
//! [`Untrusted<T>`]. This type only allows validating the data or passing it along, since copying
//! data from one userspace buffer into another is allowed for untrusted data.

use crate::prelude::Init;
use core::{
    mem::MaybeUninit,
    ops::{Index, IndexMut},
    ptr, slice,
};

/// Untrusted data of type `T`.
///
/// When reading data from userspace, hardware or other external untrusted sources, the data must
/// be validated before it is used for logic within the kernel. To do so, the [`validate()`]
/// function exists and uses the [`Validate`] trait.
///
/// Also see the [module] description.
///
/// [`validate()`]: Self::validate
/// [module]: self
#[repr(transparent)]
pub struct Untrusted<T: ?Sized>(Unvalidated<T>);

impl<T: ?Sized> Untrusted<T> {
    /// Marks the given value as untrusted.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::validate::Untrusted;
    ///
    /// # mod bindings { pub(crate) unsafe fn read_foo_info() -> [u8; 4] { todo!() } };
    /// fn read_foo_info() -> Untrusted<[u8; 4]> {
    ///     // SAFETY: just an FFI call without preconditions.
    ///     Untrusted::new(unsafe { bindings::read_foo_info() })
    /// }
    /// ```
    pub fn new(value: T) -> Self
    where
        T: Sized,
    {
        Self(Unvalidated::new(value))
    }

    /// Marks the value behind the reference as untrusted.
    ///
    /// # Examples
    ///
    /// In this imaginary example there exists the `foo_hardware` struct on the C side, as well as
    /// a `foo_hardware_read` function that reads some data directly from the hardware.
    /// ```
    /// use kernel::{error, types::Opaque, validate::Untrusted};
    /// use core::ptr;
    ///
    /// # #[allow(non_camel_case_types)]
    /// # mod bindings {
    /// #     pub(crate) struct foo_hardware;
    /// #     pub(crate) unsafe fn foo_hardware_read(_foo: *mut foo_hardware, _len: &mut usize) -> *mut u8 {
    /// #         todo!()
    /// #     }
    /// # }
    /// struct Foo(Opaque<bindings::foo_hardware>);
    ///
    /// impl Foo {
    ///     fn read(&mut self, mut len: usize) -> Result<&Untrusted<[u8]>> {
    ///         // SAFETY: just an FFI call without preconditions.
    ///         let data: *mut u8 = unsafe { bindings::foo_hardware_read(self.0.get(), &mut len) };
    ///         let data = error::from_err_ptr(data)?;
    ///         let data = ptr::slice_from_raw_parts(data, len);
    ///         // SAFETY: `data` returned by `foo_hardware_read` is valid for reads as long as the
    ///         // `foo_hardware` object exists. That function updated the
    ///         let data = unsafe { &*data };
    ///         Ok(Untrusted::new_ref(data))
    ///     }
    /// }
    /// ```
    pub fn new_ref(value: &T) -> &Self {
        let ptr: *const T = value;
        // CAST: `Self` and `Unvalidated` are `repr(transparent)` and contain a `T`.
        let ptr = ptr as *const Self;
        // SAFETY: `ptr` came from a shared reference valid for `'a`.
        unsafe { &*ptr }
    }

    /// Marks the value behind the reference as untrusted.
    ///
    /// # Examples
    ///
    /// In this imaginary example there exists the `foo_hardware` struct on the C side, as well as
    /// a `foo_hardware_read` function that reads some data directly from the hardware.
    /// ```
    /// use kernel::{error, types::Opaque, validate::Untrusted};
    /// use core::ptr;
    ///
    /// # #[allow(non_camel_case_types)]
    /// # mod bindings {
    /// #     pub(crate) struct foo_hardware;
    /// #     pub(crate) unsafe fn foo_hardware_read(_foo: *mut foo_hardware, _len: &mut usize) -> *mut u8 {
    /// #         todo!()
    /// #     }
    /// # }
    /// struct Foo(Opaque<bindings::foo_hardware>);
    ///
    /// impl Foo {
    ///     fn read(&mut self, mut len: usize) -> Result<&mut Untrusted<[u8]>> {
    ///         // SAFETY: just an FFI call without preconditions.
    ///         let data: *mut u8 = unsafe { bindings::foo_hardware_read(self.0.get(), &mut len) };
    ///         let data = error::from_err_ptr(data)?;
    ///         let data = ptr::slice_from_raw_parts_mut(data, len);
    ///         // SAFETY: `data` returned by `foo_hardware_read` is valid for reads as long as the
    ///         // `foo_hardware` object exists. That function updated the
    ///         let data = unsafe { &mut *data };
    ///         Ok(Untrusted::new_mut(data))
    ///     }
    /// }
    /// ```
    pub fn new_mut(value: &mut T) -> &mut Self {
        let ptr: *mut T = value;
        // CAST: `Self` and `Unvalidated` are `repr(transparent)` and contain a `T`.
        let ptr = ptr as *mut Self;
        // SAFETY: `ptr` came from a mutable reference valid for `'a`.
        unsafe { &mut *ptr }
    }

    /// Validates and parses the untrusted data.
    ///
    /// See the [`Validate`] trait on how to implement it.
    pub fn validate<'a, V: Validate<&'a Unvalidated<T>>>(&'a self) -> Result<V, V::Err> {
        V::validate(&self.0)
    }

    /// Validates and parses the untrusted data.
    ///
    /// See the [`Validate`] trait on how to implement it.
    pub fn validate_mut<'a, V: Validate<&'a mut Unvalidated<T>>>(
        &'a mut self,
    ) -> Result<V, V::Err> {
        V::validate(&mut self.0)
    }

    /// Sets the underlying untrusted value.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::validate::Untrusted;
    ///
    /// let mut untrusted = Untrusted::new(42);
    /// untrusted.write(24);
    /// ```
    pub fn write(&mut self, value: impl Init<T>) {
        let ptr: *mut T = &mut self.0 .0;
        // SAFETY: `ptr` came from a mutable reference and the value is overwritten before it is
        // read.
        unsafe { ptr::drop_in_place(ptr) };
        // SAFETY: `ptr` came from a mutable reference and the initializer cannot error.
        match unsafe { value.__init(ptr) } {
            Ok(()) => {}
            Err(_) => unreachable!(),
        }
    }

    /// Turns a slice of untrusted values into an untrusted slice of values.
    pub fn transpose_slice(slice: &[Untrusted<T>]) -> &Untrusted<[T]>
    where
        T: Sized,
    {
        let ptr = slice.as_ptr().cast::<T>();
        // SAFETY: `ptr` and `len` come from the same slice reference.
        let slice = unsafe { slice::from_raw_parts(ptr, slice.len()) };
        Untrusted::new_ref(slice)
    }

    /// Turns a slice of uninitialized, untrusted values into an untrusted slice of uninitialized
    /// values.
    pub fn transpose_slice_uninit(
        slice: &[MaybeUninit<Untrusted<T>>],
    ) -> &Untrusted<[MaybeUninit<T>]>
    where
        T: Sized,
    {
        let ptr = slice.as_ptr().cast::<MaybeUninit<T>>();
        // SAFETY: `ptr` and `len` come from the same mutable slice reference.
        let slice = unsafe { slice::from_raw_parts(ptr, slice.len()) };
        Untrusted::new_ref(slice)
    }

    /// Turns a slice of uninitialized, untrusted values into an untrusted slice of uninitialized
    /// values.
    pub fn transpose_slice_uninit_mut(
        slice: &mut [MaybeUninit<Untrusted<T>>],
    ) -> &mut Untrusted<[MaybeUninit<T>]>
    where
        T: Sized,
    {
        // CAST: `MaybeUninit<T>` and `MaybeUninit<Untrusted<T>>` have the same layout.
        let ptr = slice.as_mut_ptr().cast::<MaybeUninit<T>>();
        // SAFETY: `ptr` and `len` come from the same mutable slice reference.
        let slice = unsafe { slice::from_raw_parts_mut(ptr, slice.len()) };
        Untrusted::new_mut(slice)
    }
}

impl<T> Untrusted<MaybeUninit<T>> {
    /// Sets the underlying untrusted value.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::validate::Untrusted;
    ///
    /// let mut untrusted = Untrusted::new(42);
    /// untrusted.write(24);
    /// ```
    pub fn write_uninit<E>(&mut self, value: impl Init<T, E>) -> Result<&mut Untrusted<T>, E> {
        let ptr: *mut MaybeUninit<T> = &mut self.0 .0;
        // CAST: `MaybeUninit<T>` is `repr(transparent)`.
        let ptr = ptr.cast::<T>();
        // SAFETY: `ptr` came from a reference and if `Err` is returned, the underlying memory is
        // considered uninitialized.
        unsafe { value.__init(ptr) }.map(|()| {
            let this = self.0.raw_mut();
            // SAFETY: we initialized the memory above.
            Untrusted::new_mut(unsafe { this.assume_init_mut() })
        })
    }
}

impl<T> Untrusted<[MaybeUninit<T>]> {
    /// Sets the underlying untrusted value.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::validate::Untrusted;
    ///
    /// let mut untrusted = Untrusted::new(42);
    /// untrusted.write(24);
    /// ```
    pub fn write_uninit_slice<E>(
        &mut self,
        value: impl Init<[T], E>,
    ) -> Result<&mut Untrusted<[T]>, E> {
        let ptr: *mut [MaybeUninit<T>] = &mut self.0 .0;
        // CAST: `MaybeUninit<T>` is `repr(transparent)`.
        let ptr = ptr as *mut [T];
        // SAFETY: `ptr` came from a reference and if `Err` is returned, the underlying memory is
        // considered uninitialized.
        unsafe { value.__init(ptr) }.map(|()| {
            let this = self.0.raw_mut().as_mut_ptr();
            // CAST: `MaybeUninit<T>` is `repr(transparent)`.
            let this = this.cast::<T>();
            // SAFETY: `this` and `len` came from the same slice reference.
            let this = unsafe { slice::from_raw_parts_mut(this, self.0.len()) };
            Untrusted::new_mut(this)
        })
    }
}

/// Marks types that can be used as input to [`Validate::validate`].
pub trait ValidateInput: private::Sealed + Sized {}

mod private {
    pub trait Sealed {}
}

impl<'a, T: ?Sized> private::Sealed for &'a Unvalidated<T> {}
impl<'a, T: ?Sized> ValidateInput for &'a Unvalidated<T> {}

impl<'a, T: ?Sized> private::Sealed for &'a mut Unvalidated<T> {}
impl<'a, T: ?Sized> ValidateInput for &'a mut Unvalidated<T> {}

/// Validates untrusted data.
///
/// # Examples
///
/// The simplest way to validate data is to just implement `Validate<&Unvalidated<[u8]>>` for the
/// type that you wish to validate:
///
/// ```
/// use kernel::{
///     error::{code::EINVAL, Error},
///     str::{CStr, CString},
///     validate::{Unvalidated, Validate},
/// };
///
/// struct Data {
///     flags: u8,
///     name: CString,
/// }
///
/// impl Validate<&Unvalidated<[u8]>> for Data {
///     type Err = Error;
///
///     fn validate(unvalidated: &Unvalidated<[u8]>) -> Result<Self, Self::Err> {
///         let raw = unvalidated.raw();
///         let (&flags, name) = raw.split_first().ok_or(EINVAL)?;
///         let name = CStr::from_bytes_with_nul(name)?.to_cstring()?;
///         Ok(Data { flags, name })
///     }
/// }
/// ```
///
/// This approach copies the data and requires allocation. If you want to avoid the allocation and
/// copying the data, you can borrow from the input like this:
///
/// ```
/// use kernel::{
///     error::{code::EINVAL, Error},
///     str::CStr,
///     validate::{Unvalidated, Validate},
/// };
///
/// struct Data<'a> {
///     flags: u8,
///     name: &'a CStr,
/// }
///
/// impl<'a> Validate<&'a Unvalidated<[u8]>> for Data<'a> {
///     type Err = Error;
///
///     fn validate(unvalidated: &'a Unvalidated<[u8]>) -> Result<Self, Self::Err> {
///         let raw = unvalidated.raw();
///         let (&flags, name) = raw.split_first().ok_or(EINVAL)?;
///         let name = CStr::from_bytes_with_nul(name)?;
///         Ok(Data { flags, name })
///     }
/// }
/// ```
///
/// If you need to in-place validate your data, you currently need to resort to `unsafe`:
///
/// ```
/// use kernel::{
///     error::{code::EINVAL, Error},
///     str::CStr,
///     validate::{Unvalidated, Validate},
/// };
/// use core::mem;
///
/// // Important: use `repr(C)`, this ensures a linear layout of this type.
/// #[repr(C)]
/// struct Data {
///     version: u8,
///     flags: u8,
///     _reserved: [u8; 2],
///     count: u64,
///     // lots of other fields...
/// }
///
/// impl Validate<&Unvalidated<[u8]>> for &Data {
///     type Err = Error;
///
///     fn validate(unvalidated: &Unvalidated<[u8]>) -> Result<Self, Self::Err> {
///         let raw = unvalidated.raw();
///         if raw.len() < mem::size_of::<Data>() {
///             return Err(EINVAL);
///         }
///         // can only handle version 0
///         if raw[0] != 0 {
///             return Err(EINVAL);
///         }
///         // version 0 only uses the lower 4 bits of flags
///         if raw[1] & 0xf0 != 0 {
///             return Err(EINVAL);
///         }
///         let ptr = raw.as_ptr();
///         // CAST: `Data` only contains integers and has `repr(C)`.
///         let ptr = ptr.cast::<Data>();
///         // SAFETY: `ptr` came from a reference and the cast above is valid.
///         Ok(unsafe { &*ptr })
///     }
/// }
/// ```
///
/// To be able to modify the parsed data, while still supporting zero-copy, you can implement
/// `Validate<&mut Unvalidated<[u8]>>`:
///
/// ```
/// use kernel::{
///     error::{code::EINVAL, Error},
///     str::CStr,
///     validate::{Unvalidated, Validate},
/// };
/// use core::mem;
///
/// // Important: use `repr(C)`, this ensures a linear layout of this type.
/// #[repr(C)]
/// struct Data {
///     version: u8,
///     flags: u8,
///     _reserved: [u8; 2],
///     count: u64,
///     // lots of other fields...
/// }
///
/// impl Validate<&mut Unvalidated<[u8]>> for &Data {
///     type Err = Error;
///
///     fn validate(unvalidated: &mut Unvalidated<[u8]>) -> Result<Self, Self::Err> {
///         let raw = unvalidated.raw_mut();
///         if raw.len() < mem::size_of::<Data>() {
///             return Err(EINVAL);
///         }
///         match raw[0] {
///             0 => {},
///             1 => {
///                 // version 1 implicitly sets the first bit.
///                 raw[1] |= 1;
///             },
///             // can only handle version 0 and 1
///             _ => return Err(EINVAL),
///         }
///         // version 0 and 1 only use the lower 4 bits of flags
///         if raw[1] & 0xf0 != 0 {
///             return Err(EINVAL);
///         }
///         if raw[1] == 0 {}
///         let ptr = raw.as_ptr();
///         // CAST: `Data` only contains integers and has `repr(C)`.
///         let ptr = ptr.cast::<Data>();
///         // SAFETY: `ptr` came from a reference and the cast above is valid.
///         Ok(unsafe { &*ptr })
///     }
/// }
/// ```
pub trait Validate<I: ValidateInput>: Sized {
    /// Validation error.
    type Err;

    /// Validate the given untrusted data and parse it into the output type.
    fn validate(unvalidated: I) -> Result<Self, Self::Err>;
}

/// Unvalidated data of type `T`.
#[repr(transparent)]
pub struct Unvalidated<T: ?Sized>(T);

impl<T: ?Sized> Unvalidated<T> {
    fn new(value: T) -> Self
    where
        T: Sized,
    {
        Self(value)
    }

    fn new_ref(value: &T) -> &Self {
        let ptr: *const T = value;
        // CAST: `Self` is `repr(transparent)` and contains a `T`.
        let ptr = ptr as *const Self;
        // SAFETY: `ptr` came from a mutable reference valid for `'a`.
        unsafe { &*ptr }
    }

    fn new_mut(value: &mut T) -> &mut Self {
        let ptr: *mut T = value;
        // CAST: `Self` is `repr(transparent)` and contains a `T`.
        let ptr = ptr as *mut Self;
        // SAFETY: `ptr` came from a mutable reference valid for `'a`.
        unsafe { &mut *ptr }
    }

    /// Validates and parses the untrusted data.
    ///
    /// See the [`Validate`] trait on how to implement it.
    pub fn validate_ref<'a, V: Validate<&'a Unvalidated<T>>>(&'a self) -> Result<V, V::Err> {
        V::validate(self)
    }

    /// Validates and parses the untrusted data.
    ///
    /// See the [`Validate`] trait on how to implement it.
    pub fn validate_mut<'a, V: Validate<&'a mut Unvalidated<T>>>(
        &'a mut self,
    ) -> Result<V, V::Err> {
        V::validate(self)
    }

    /// Gives immutable access to the underlying value.
    pub fn raw(&self) -> &T {
        &self.0
    }

    /// Gives mutable access to the underlying value.
    pub fn raw_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T, I> Index<I> for Unvalidated<[T]>
where
    I: slice::SliceIndex<[T]>,
{
    type Output = Unvalidated<I::Output>;

    fn index(&self, index: I) -> &Self::Output {
        Unvalidated::new_ref(self.0.index(index))
    }
}

impl<T, I> IndexMut<I> for Unvalidated<[T]>
where
    I: slice::SliceIndex<[T]>,
{
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        Unvalidated::new_mut(self.0.index_mut(index))
    }
}

/// Immutable unvalidated slice iterator.
pub struct Iter<'a, T>(slice::Iter<'a, T>);

/// Mutable unvalidated slice iterator.
pub struct IterMut<'a, T>(slice::IterMut<'a, T>);

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a Unvalidated<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Unvalidated::new_ref)
    }
}

impl<'a, T> IntoIterator for &'a Unvalidated<[T]> {
    type Item = &'a Unvalidated<T>;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        Iter(self.0.iter())
    }
}

impl<'a, T> Iterator for IterMut<'a, T> {
    type Item = &'a mut Unvalidated<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Unvalidated::new_mut)
    }
}

impl<'a, T> IntoIterator for &'a mut Unvalidated<[T]> {
    type Item = &'a mut Unvalidated<T>;
    type IntoIter = IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        IterMut(self.0.iter_mut())
    }
}

impl<T> Unvalidated<[T]> {
    /// Returns the number of elements in the underlying slice.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the underlying slice has a length of 0.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates over all items and validates each of them individually.
    pub fn validate_iter<'a, V: Validate<&'a Unvalidated<T>>>(
        &'a self,
    ) -> impl Iterator<Item = Result<V, V::Err>> + 'a {
        self.into_iter().map(|item| V::validate(item))
    }

    /// Iterates over all items and validates each of them individually.
    pub fn validate_iter_mut<'a, V: Validate<&'a mut Unvalidated<T>>>(
        &'a mut self,
    ) -> impl Iterator<Item = Result<V, V::Err>> + 'a {
        self.into_iter().map(|item| V::validate(item))
    }
}
