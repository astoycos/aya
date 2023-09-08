//! Pinning BPF objects to the BPF filesystem.

use crate::sys::SyscallError;
use std::fmt;
use thiserror::Error;

/// An error ocurred working with a pinned BPF object.
#[derive(Error, Debug)]
pub enum PinError {
    /// The object has already been pinned.
    #[error("the BPF object `{name}` has already been pinned")]
    AlreadyPinned {
        /// Object name.
        name: String,
    },
    /// The object FD is not known by Aya.
    #[error("the BPF object `{name}`'s FD is not known")]
    NoFd {
        /// Object name.
        name: String,
    },
    /// The path for the BPF object is not valid.
    #[error("invalid pin path `{}`", path.display())]
    InvalidPinPath {
        /// The path.
        path: std::path::PathBuf,

        #[source]
        /// The source error.
        error: std::ffi::NulError,
    },
    /// An error ocurred making a syscall.
    #[error(transparent)]
    SyscallError(#[from] SyscallError),

    /// An error occured unpinning an object.
    #[error("failed to remove pin for object {name}:\n{errors}")]
    UnpinError {
        /// Object name.
        name: String,

        /// Path to io error mappings.
        errors: PinIOErrors,
    },
}

// PathError describes a single failed attempt to pin a bpf object to a bpf
// filesystem.
#[derive(Debug)]
pub(crate) struct PinIOError {
    /// The paths.
    path: std::path::PathBuf,

    /// The source error
    error: std::io::Error,
}

impl PinIOError {
    pub(crate) fn new(path: std::path::PathBuf, error: std::io::Error) -> Self {
        PinIOError { path, error }
    }
}

/// PinIOErrors reports an a set of io errors which can occur when handling
/// a map pin path.
#[derive(Debug)]
pub struct PinIOErrors(pub(crate) Vec<PinIOError>);

impl fmt::Display for PinIOErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for i in &self.0 {
            write!(f, "{}: {}\n", &i.path.display(), i.error)?;
        }
        Ok(())
    }
}
