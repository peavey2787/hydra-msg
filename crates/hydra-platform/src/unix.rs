//! Unix `flock` binding for exclusive profile locks.

use std::{fs::File, io, os::unix::io::AsRawFd};

const LOCK_EX: i32 = 2;
const LOCK_NB: i32 = 4;

extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

pub(crate) fn lock_exclusive(file: &File) -> io::Result<bool> {
    if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(error)
    }
}
