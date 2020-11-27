use std::ffi::CStr;
use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

/// Represents an error that could occur when interacting with `libseccomp`.
///
/// If the `libseccomp` function returns `-ECANCELED`, then [`code()`] will give the value of
/// `errno` immediately after the call, and [`is_system()`] will return `true`.
///
/// Otherwise, [`code()`] will give the error code returned by `libseccomp`, and [`is_system()`]
/// will return `false`.
///
/// [`code()`]: ./fn.code.html
/// [`is_system()`]: ./fn.is_system.html
#[derive(Clone)]
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

    /// Returns the raw OS error code (i.e. an `errno` value).
    #[inline]
    pub fn code(&self) -> i32 {
        self.code
    }

    /// Returns whether this is a system error instead of a libseccomp error.
    ///
    /// (i.e. if this function returns `true` then a `libseccomp` function returned `-ECANCELED`.)
    #[inline]
    pub fn is_system(&self) -> bool {
        self.is_errno
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

#[cfg(test)]
mod tests {
    use super::*;

    fn set_errno(eno: libc::c_int) {
        unsafe {
            *libc::__errno_location() = eno;
        }
    }

    fn assert_same(err1: &Error, err2: &Error) {
        assert_eq!(err1.code, err2.code);
        assert_eq!(err1.is_errno, err2.is_errno);
    }

    #[test]
    fn test_new() {
        assert_same(
            &Error::new(libc::ENOENT),
            &Error {
                code: libc::ENOENT,
                is_errno: false,
            },
        );

        set_errno(libc::EEXIST);
        assert_same(
            &Error::new(libc::ECANCELED),
            &Error {
                code: libc::EEXIST,
                is_errno: true,
            },
        );
    }

    #[test]
    fn test_unpack() {
        assert_eq!(Error::unpack(0).unwrap(), 0);
        assert_eq!(Error::unpack(1).unwrap(), 1);

        assert_same(
            &Error::unpack(-libc::ENOENT).unwrap_err(),
            &Error {
                code: libc::ENOENT,
                is_errno: false,
            },
        );

        set_errno(libc::EEXIST);
        assert_same(
            &Error::unpack(-libc::ECANCELED).unwrap_err(),
            &Error {
                code: libc::EEXIST,
                is_errno: true,
            },
        );
    }

    #[test]
    fn test_debug() {
        assert_eq!(
            format!("{:?}", Error::new(libc::ENOENT)),
            format!(
                "Error {{ code: {}, is_system: false, message: \"Does not exist\" }}",
                libc::ENOENT
            )
        );

        set_errno(libc::ENOENT);
        let err = Error::new(libc::ECANCELED);
        assert_eq!(
            format!("{:?}", err),
            format!(
                "Error {{ code: {}, is_system: true, message: \"{}\" }}",
                libc::ENOENT,
                err.strerror()
            )
        );
    }

    #[test]
    fn test_display_and_into() {
        use std::io;

        for (eno, kind, msg) in [
            (
                libc::ENOENT,
                io::ErrorKind::NotFound,
                Some("Does not exist"),
            ),
            (
                libc::EEXIST,
                io::ErrorKind::AlreadyExists,
                Some("Already exists"),
            ),
            (
                libc::EINVAL,
                io::ErrorKind::InvalidInput,
                Some("Invalid argument"),
            ),
            (libc::EACCES, io::ErrorKind::PermissionDenied, None),
            (libc::EPERM, io::ErrorKind::PermissionDenied, None),
            (
                libc::ESRCH,
                io::ErrorKind::Other,
                Some("Unable to load due to thread issues"),
            ),
            (
                libc::EFAULT,
                io::ErrorKind::Other,
                Some("Internal libseccomp error"),
            ),
        ]
        .iter()
        {
            let orig_err = Error::unpack(-eno).unwrap_err();

            let io_err = io::Error::from(orig_err.clone());
            assert_eq!(io_err.raw_os_error(), None);
            assert_eq!(io_err.kind(), *kind);

            if let Some(msg) = msg {
                assert_eq!(io_err.to_string(), *msg);

                assert_eq!(orig_err.strerror(), *msg);
                assert_eq!(orig_err.to_string(), format!("{} (libseccomp error)", msg));

                #[allow(deprecated)]
                {
                    use std::error::Error;
                    assert_eq!(orig_err.description(), *msg);
                }
            }
        }

        set_errno(libc::ENOENT);
        let orig_err = Error::unpack(-libc::ECANCELED).unwrap_err();
        assert_eq!(
            orig_err.to_string(),
            format!(
                "{} (system error, code {})",
                orig_err.strerror(),
                libc::ENOENT
            )
        );

        let io_err = io::Error::from(orig_err);
        assert_eq!(io_err.raw_os_error(), Some(libc::ENOENT));
        assert_eq!(io_err.raw_os_error(), Some(libc::ENOENT));
    }
}
