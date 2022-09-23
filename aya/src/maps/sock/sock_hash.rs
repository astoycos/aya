use std::{
    marker::PhantomData,
    os::unix::io::{AsRawFd, RawFd},
};

use crate::{
    maps::{
        hash_map, sock::SocketMap, IterableMap, MapError, MapIter, MapKeys, MapRef, MapRefMut, MapData,
    },
    sys::bpf_map_lookup_elem,
    Pod,
};

/// A hash map of TCP or UDP sockets.
///
/// A `SockHash` is used to store TCP or UDP sockets. eBPF programs can then be
/// attached to the map to inspect, filter or redirect network buffers on those
/// sockets.
///
/// A `SockHash` can also be used to redirect packets to sockets contained by the
/// map using `bpf_redirect_map()`, `bpf_sk_redirect_hash()` etc.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.18.
///
/// # Examples
///
/// ```no_run
/// # #[derive(Debug, thiserror::Error)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     IO(#[from] std::io::Error),
/// #     #[error(transparent)]
/// #     Map(#[from] aya::maps::MapError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use std::io::Write;
/// use std::net::TcpStream;
/// use std::os::unix::io::AsRawFd;
/// use aya::maps::SockHash;
/// use aya::programs::SkMsg;
///
/// let mut intercept_egress = SockHash::try_from(bpf.map_mut("INTERCEPT_EGRESS")?)?;
/// let prog: &mut SkMsg = bpf.program_mut("intercept_egress_packet").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(&intercept_egress)?;
///
/// let mut client = TcpStream::connect("127.0.0.1:1234")?;
/// intercept_egress.insert(1234, client.as_raw_fd(), 0)?;
///
/// // the write will be intercepted
/// client.write_all(b"foo")?;
/// # Ok::<(), Error>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_SOCKHASH")]
pub struct SockHash<K> {
    data: MapData,
    _k: PhantomData<K>,
}

impl<K: Pod> SockHash<K> {
    fn new(map: MapData) -> Result<SockHash<K>, MapError> {
        hash_map::check_kv_size::<K, u32>(&map)?;
        let _ = map.fd_or_err()?;

        Ok(SockHash {
            data: map,
            _k: PhantomData,
        })
    }

    /// Returns the fd of the socket stored at the given key.
    pub fn get(&self, key: &K, flags: u64) -> Result<RawFd, MapError> {
        let fd = self.data.deref().fd_or_err()?;
        let value = bpf_map_lookup_elem(fd, key, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                io_error,
            }
        })?;
        value.ok_or(MapError::KeyNotFound)
    }

    /// An iterator visiting all key-value pairs in arbitrary order. The
    /// iterator item type is `Result<(K, V), MapError>`.
    pub fn iter(&self) -> MapIter<'_, K, RawFd, Self> {
        MapIter::new(self)
    }

    /// An iterator visiting all keys in arbitrary order. The iterator element
    /// type is `Result<K, MapError>`.
    pub fn keys(&self) -> MapKeys<'_, K> {
        MapKeys::new(&self.data)
    }

    /// Inserts a socket under the given key.
    pub fn insert<I: AsRawFd>(&mut self, key: K, value: I, flags: u64) -> Result<(), MapError> {
        hash_map::insert(&mut self.data, key, value.as_raw_fd(), flags)
    }

    /// Removes a socket from the map.
    pub fn remove(&mut self, key: &K) -> Result<(), MapError> {
        hash_map::remove(&mut self.data, key)
    }

    fn map(&self) -> &MapData {
        &self.data
    }

    fn get(&self, key: &K) -> Result<RawFd, MapError> {
        SockHash::get(self, key, 0)
    }

    fn fd_or_err(&self) -> Result<RawFd, MapError> {
        self.data.fd_or_err()
    }
}
