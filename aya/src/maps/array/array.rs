use std::{
    marker::PhantomData, os::unix::prelude::RawFd,
};

use crate::{
    maps::{MapError, MapData, IterableMap},
    sys::{bpf_map_lookup_elem, bpf_map_update_elem},
    Pod,
};

/// A fixed-size array.
///
/// The size of the array is defined on the eBPF side using the `bpf_map_def::max_entries` field.
/// All the entries are zero-initialized when the map is created.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 3.19.
///
/// # Examples
/// ```no_run
/// # let bpf = aya::Bpf::load(&[])?;
/// use aya::maps::Array;
///
/// let mut array = Array::try_from(bpf.map_mut("ARRAY")?)?;
/// array.set(1, 42, 0)?;
/// assert_eq!(array.get(&1, 0)?, 42);
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_ARRAY")]
pub struct Array<V> {
    fd: RawFd,
    max_entries: u32,
    _v: PhantomData<V>,
}

impl<V: Pod> Array<V> {
    /// Returns the number of elements in the array.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn len(&self) -> u32 {
        self.max_entries
    }

    /// Returns the value stored at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_elem` fails.
    pub fn get(&self, index: &u32, flags: u64) -> Result<V, MapError> {
        self.check_bounds(*index)?;
        let fd = self.fd;

        let value = bpf_map_lookup_elem(fd, index, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                io_error,
            }
        })?;
        value.ok_or(MapError::KeyNotFound)
    }

    /// An iterator over the elements of the array. The iterator item type is `Result<V,
    /// MapError>`.
    pub fn iter(&self) -> impl Iterator<Item = Result<V, MapError>> + '_ {
        (0..self.len()).map(move |i| self.get(&i, 0))
    }

    fn check_bounds(&self, index: u32) -> Result<(), MapError> {
        let max_entries = self.max_entries;
        if index >= max_entries {
            Err(MapError::OutOfBounds { index, max_entries })
        } else {
            Ok(())
        }
    }

    /// Sets the value of the element at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails.
    pub fn set(&mut self, index: u32, value: V, flags: u64) -> Result<(), MapError> {
        let fd = self.fd;
        self.check_bounds(index)?;
        bpf_map_update_elem(fd, Some(&index), &value, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                io_error,
            }
        })?;
        Ok(())
    }

}

impl<V: Pod> IterableMap<u32, V> for Array<V> {
    fn fd(&self) -> &RawFd {
        &self.fd
    }

    fn get(&self, index: &u32) -> Result<V, MapError> {
        self.get(index, 0)
    }
}