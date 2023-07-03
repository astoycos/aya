//! Common functions shared between multiple eBPF program types.
use chrono::{prelude::DateTime, Local};
use std::{
    ffi::CStr,
    fs::File,
    io,
    io::{BufRead, BufReader},
    os::unix::io::RawFd,
    path::Path,
    time::{Duration, UNIX_EPOCH},
};

use crate::{
    programs::{FdLink, Link, ProgramData, ProgramError},
    sys::bpf_raw_tracepoint_open,
};

/// Attaches the program to a raw tracepoint.
pub(crate) fn attach_raw_tracepoint<T: Link + From<FdLink>>(
    program_data: &mut ProgramData<T>,
    tp_name: Option<&CStr>,
) -> Result<T::Id, ProgramError> {
    let prog_fd = program_data.fd_or_err()?;

    let pfd = bpf_raw_tracepoint_open(tp_name, prog_fd).map_err(|(_code, io_error)| {
        ProgramError::SyscallError {
            call: "bpf_raw_tracepoint_open".to_owned(),
            io_error,
        }
    })? as RawFd;

    program_data.links.insert(FdLink::new(pfd).into())
}

/// Find tracefs filesystem path.
pub(crate) fn find_tracefs_path() -> Result<&'static Path, ProgramError> {
    lazy_static::lazy_static! {
        static ref TRACE_FS: Option<&'static Path> = {
            let known_mounts = [
                Path::new("/sys/kernel/tracing"),
                Path::new("/sys/kernel/debug/tracing"),
            ];

            for mount in known_mounts {
                // Check that the mount point exists and is not empty
                // Documented here: (https://www.kernel.org/doc/Documentation/trace/ftrace.txt)
                // In some cases, tracefs will only mount at /sys/kernel/debug/tracing
                // but, the kernel will still create the directory /sys/kernel/tracing.
                // The user may be expected to manually mount the directory in order for it to
                // exist in /sys/kernel/tracing according to the documentation.
                if mount.exists() && mount.read_dir().ok()?.next().is_some() {
                    return Some(mount);
                }
            }
            None
        };
    }

    TRACE_FS
        .as_deref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "tracefs not found").into())
}

/// Get the program's load time.
///
/// The load time is specified by the kernel as nanoseconds since system boot,
/// this function converts that u64 value into a human readable string.
pub(crate) fn print_load_time(ns_since_boot: u64) -> String {
    let time_boot = nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME).unwrap();
    let time_real = nix::time::clock_gettime(nix::time::ClockId::CLOCK_REALTIME).unwrap();

    let wallclock_secs = (time_real.tv_sec() - time_boot.tv_sec())
        + (time_real.tv_nsec() - time_boot.tv_nsec() + ns_since_boot as i64) / 1000000000;
    let d = UNIX_EPOCH + Duration::from_secs(wallclock_secs as u64);

    DateTime::<Local>::from(d)
        .format("%Y-%m-%dT%H:%M:%S%z")
        .to_string()
}

/// Get the specified key information in `/proc/self/
pub(crate) fn get_fdinfo(fd: RawFd, key: &str) -> Result<u32, ProgramError> {
    let info = File::open(format!("/proc/self/fdinfo/{}", fd)).unwrap();
    let reader = BufReader::new(info);

    for line in reader.lines() {
        match line {
            Ok(l) => {
                if !l.contains(key) {
                    continue;
                }

                let parts = l.split('\t');

                return Ok(parts.last().unwrap_or("err").parse().unwrap_or(0));
            }
            Err(e) => return Err(ProgramError::IOError(e)),
        }
    }

    Ok(0)
}
