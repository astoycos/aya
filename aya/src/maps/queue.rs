//! A FIFO queue.
use std::{
    marker::PhantomData,
    mem,
};

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_QUEUE,
    maps::MapError,
    sys::{bpf_map_lookup_and_delete_elem, bpf_map_push_elem},
    Pod,
};

use super::MapData;

/// A FIFO queue.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.20.
///
/// # Examples
/// ```no_run
/// # let bpf = aya::Bpf::load(&[])?;
/// use aya::maps::Queue;
///
/// let mut queue = Queue::try_from(bpf.map_mut("ARRAY")?)?;
/// queue.push(42, 0)?;
/// queue.push(43, 0)?;
/// assert_eq!(queue.pop(0)?, 42);
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_QUEUE")]
pub struct Queue<V: Pod> {
    data: MapData,
    _v: PhantomData<V>,
}

impl<V: Pod> Queue<V> {
    fn new(map: MapData) -> Result<Queue<V>, MapError> {
        let map_type = map.obj.map_type();
        if map_type != BPF_MAP_TYPE_QUEUE as u32 {
            return Err(MapError::InvalidMapType {
                map_type: map_type as u32,
            });
        }
        let expected = 0;
        let size = map.obj.key_size() as usize;
        if size != expected {
            return Err(MapError::InvalidKeySize { size, expected });
        }

        let expected = mem::size_of::<V>();
        let size = map.obj.value_size() as usize;
        if size != expected {
            return Err(MapError::InvalidValueSize { size, expected });
        }
        let _fd = map.fd_or_err()?;

        Ok(Queue {
            data: map,
            _v: PhantomData,
        })
    }

    /// Returns the number of elements the queue can hold.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn capacity(&self) -> u32 {
        self.data.obj.max_entries()
    }

        /// Removes the first element and returns it.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::ElementNotFound`] if the queue is empty, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_and_delete_elem` fails.
    pub fn pop(&mut self, flags: u64) -> Result<V, MapError> {
        let fd = self.data.fd_or_err()?;

        let value = bpf_map_lookup_and_delete_elem::<u32, _>(fd, None, flags).map_err(
            |(_, io_error)| MapError::SyscallError {
                call: "bpf_map_lookup_and_delete_elem".to_owned(),
                io_error,
            },
        )?;
        value.ok_or(MapError::ElementNotFound)
    }

    /// Appends an element at the end of the queue.
    ///
    /// # Errors
    ///
    /// [`MapError::SyscallError`] if `bpf_map_update_elem` fails.
    pub fn push(&mut self, value: V, flags: u64) -> Result<(), MapError> {
        let fd = self.data.fd_or_err()?;
        bpf_map_push_elem(fd, &value, flags).map_err(|(_, io_error)| MapError::SyscallError {
            call: "bpf_map_push_elem".to_owned(),
            io_error,
        })?;
        Ok(())
    }
}
