use std::ffi::CStr;
use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

pub struct Error {
    code: i32,
    is_errno: bool,
}

impl Error {
    pub(crate) fn new(code: i32) -> Self {
        if code == libc::ECANCELED {
            Self {
                code: unsafe { *libc::__errno_location() },
                is_errno: true,
            }
        } else {
            Self {
                code,
                is_errno: false,
            }
        }
    }

    #[inline]
    pub(crate) fn unpack(res: i32) -> Result<i32> {
        if res < 0 {
            Err(Self::new(-res))
        } else {
            Ok(res)
        }
    }

    // Identical to unpack(), but translates -EEXIST to -ENOENT (sometimes libseccomp returns -EEXIST
    // when it really means -ENOENT)
    #[inline]
    pub(crate) fn unpack_enoent(res: i32) -> Result<i32> {
        if res == -libc::EEXIST {
            Err(Self {
                code: libc::ENOENT,
                is_errno: false,
            })
        } else {
            Self::unpack(res)
        }
    }

    #[inline]
    pub fn code(&self) -> i32 {
        self.code
    }

    fn strerror(&self) -> &'static str {
        if !self.is_errno {
            match self.code {
                libc::EDOM => return "Architecture-specific failure",
                libc::EEXIST => return "Already exists",
                libc::ENOENT => return "Does not exist",
                libc::ESRCH => return "Unable to load due to thread issues",
                libc::EFAULT => return "Internal libseccomp error",
                _ => (),
            }
        }

        unsafe { CStr::from_ptr(libc::strerror(self.code)) }
            .to_str()
            .unwrap()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.strerror())?;

        if self.is_errno {
            write!(f, " (system error, code {})", self.code)
        } else {
            write!(f, " (libseccomp error)")
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Error")
            .field("code", &self.code)
            .field("is_system", &self.is_errno)
            .field("message", &self.strerror())
            .finish()
    }
}

impl std::error::Error for Error {
    #[inline]
    fn description(&self) -> &str {
        self.strerror()
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        if e.is_errno {
            Self::from_raw_os_error(e.code)
        } else {
            use std::io::ErrorKind;

            let kind = match e.code {
                libc::ENOENT => ErrorKind::NotFound,
                libc::EEXIST => ErrorKind::AlreadyExists,
                libc::EINVAL => ErrorKind::InvalidInput,
                libc::EACCES | libc::EPERM => ErrorKind::PermissionDenied,
                _ => ErrorKind::Other,
            };

            Self::new(kind, e.strerror())
        }
    }
}
