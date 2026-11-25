use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

fn at(parent: &File, name: &CStr, directory: bool) -> io::Result<File> {
    let mut flags = libc::O_CLOEXEC | libc::O_RDONLY | libc::O_NOFOLLOW;
    if directory {
        flags |= libc::O_DIRECTORY;
    }
    // SAFETY: valid borrowed directory fd and NUL-terminated single component.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn mount_id(file: &File) -> io::Result<u64> {
    let raw = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
    raw.lines()
        .find_map(|s| s.strip_prefix("mnt_id:")?.trim().parse().ok())
        .ok_or_else(|| io::Error::other("cannot establish cgroup mount identity"))
}

pub fn open_empty(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::other("select an absolute cgroup path"));
    }
    let mut dir = File::open("/")?;
    let mut parent = None;
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(part) => {
                let next = at(&dir, &CString::new(part.as_bytes())?, true)?;
                parent = Some(std::mem::replace(&mut dir, next));
            }
            _ => return Err(io::Error::other("invalid cgroup path")),
        }
    }
    let parent = parent.ok_or_else(|| io::Error::other("select a child cgroup"))?;
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: successful fstatfs initializes the structure.
    if unsafe { libc::fstatfs(dir.as_raw_fd(), fs.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { fs.assume_init() }.f_type as u64 != 0x63677270 {
        return Err(io::Error::other("target is not a cgroup v2 directory"));
    }
    if mount_id(&dir)? != mount_id(&parent)? || dir.metadata()?.ino() == parent.metadata()?.ino() {
        return Err(io::Error::other("refusing cgroup mount root"));
    }
    let mut events = String::new();
    at(&dir, c"cgroup.events", false)?
        .take(4096)
        .read_to_string(&mut events)?;
    if !events.lines().any(|line| line == "populated 0") {
        return Err(io::Error::other(
            "select an empty cgroup before launching workloads",
        ));
    }
    Ok(dir)
}
