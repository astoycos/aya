//! An array of eBPF program file descriptors used as a jump table.

use std::{
    mem,
    os::unix::{io::AsRawFd, prelude::RawFd},
};

use crate::{
    maps::{sock::SocketMap, MapError, MapKeys,MapData},
    sys::{bpf_map_delete_elem, bpf_map_update_elem},
};

/// An array of TCP or UDP sockets.
///
/// A `SockMap` is used to store TCP or UDP sockets. eBPF programs can then be
/// attached to the map to inspect, filter or redirect network buffers on those
/// sockets.
///
/// A `SockMap` can also be used to redirect packets to sockets contained by the
/// map using `bpf_redirect_map()`, `bpf_sk_redirect_map()` etc.    
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.14.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::maps::SockMap;
/// use aya::programs::SkSkb;
///
/// let intercept_ingress = SockMap::try_from(bpf.map_mut("INTERCEPT_INGRESS")?)?;
/// let prog: &mut SkSkb = bpf.program_mut("intercept_ingress_packet").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(&intercept_ingress)?;
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_SOCKMAP")]
pub struct SockMap {
    fd: RawFd,
    max_entries: u32,
}

impl SockMap {
    /// An iterator over the indices of the array that point to a program. The iterator item type
    /// is `Result<u32, MapError>`.
    pub fn indices(&self) -> MapKeys<'_, u32> {
        MapKeys::new(&self.fd)
    }

    fn check_bounds(&self, index: u32) -> Result<(), MapError> {
        let max_entries = self.max_entries;
        if index >= max_entries {
            Err(MapError::OutOfBounds { index, max_entries })
        } else {
            Ok(())
        }
    }

    /// Stores a socket into the map.
    pub fn set<I: AsRawFd>(&mut self, index: u32, socket: &I, flags: u64) -> Result<(), MapError> {
        let fd = self.fd;
        self.check_bounds(index)?;
        bpf_map_update_elem(fd, Some(&index), &socket.as_raw_fd(), flags).map_err(
            |(_, io_error)| MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                io_error,
            },
        )?;
        Ok(())
    }

    /// Removes the socket stored at `index` from the map.
    pub fn clear_index(&mut self, index: &u32) -> Result<(), MapError> {
        let fd = self.fd;
        self.check_bounds(*index)?;
        bpf_map_delete_elem(fd, index)
            .map(|_| ())
            .map_err(|(_, io_error)| MapError::SyscallError {
                call: "bpf_map_delete_elem".to_owned(),
                io_error,
            })
    }
}
