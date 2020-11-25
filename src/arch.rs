use std::fmt;

use crate::sys;

macro_rules! define_arch {
    ($($name:tt,)*) => {
        /// An architecture supported by `libseccomp`.
        #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
        #[repr(u32)]
        pub enum Arch {
            /// Represents the "native" architecture; i.e. the current system architecture.
            ///
            /// In general, specifying this is equivalent to specifying
            /// [`Arch::native()`](#method.native).
            NATIVE = sys::SCMP_ARCH::NATIVE,
            $(
                $name = sys::SCMP_ARCH::$name,
            )*
        }

        static ALL_ARCHES: &[Arch] = &[
            $(
                Arch::$name,
            )*
        ];

        static ALL_ARCH_NAMES: &[&str] = &[
            $(
                stringify!($name),
            )*
        ];
    };
}

// No, this does not include NATIVE; it's added to the enum automatically.
// It isn't in this list because we want to keep it out of ALL_ARCHES since it isn't technically an
// "architecture."

define_arch!(
    X86,
    X86_64,
    X32,
    ARM,
    AARCH64,
    MIPS,
    MIPS64,
    MIPS64N32,
    MIPSEL,
    MIPSEL64,
    MIPSEL64N32,
    PPC,
    PPC64,
    PPC64LE,
    S390,
    S390X,
    // parisc and parisc64 were added in v2.4.0
    PARISC,
    PARISC64,
    // riscv64 was added in v2.5.0
    RISCV64,
    // IMPORTANT: Architectures must be added to this list in the same order as they received
    // support in libseccomp.
    // Arch::all() assumes that this is true when probing for supported architectures.
);

impl Arch {
    /// Return a slice listing all architectures supported by the installed version of `libseccomp`.
    ///
    /// This probes the currently loaded `libseccomp` to determine whether it supports architectures
    /// that were only added in recent versions of `libseccomp`.
    pub fn all() -> &'static [Self] {
        let mut end;

        if cfg!(feature = "libseccomp-2-5") {
            // Assume all architectures up through and including riscv64 are supported
            end = 19;
        } else if cfg!(feature = "libseccomp-2-4") {
            // Assume all architectures up through and including parisc (but not necessarily
            // riscv64) are supported

            end = 18;
            debug_assert_eq!(ALL_ARCHES[end], Arch::RISCV64);
        } else {
            // Assume all architectures up through and including s390x (but not necessarily
            // parisc/parisc64/riscv64) are supported

            end = 16;
            debug_assert_eq!(ALL_ARCHES[end], Arch::PARISC);
        }

        // Sanity check: make sure the previous architecture is supported
        debug_assert!(ALL_ARCHES[end - 1].is_supported());

        loop {
            match ALL_ARCHES.get(end) {
                Some(arch) if arch.is_supported() => {
                    end += 1;
                }
                _ => return &ALL_ARCHES[..end],
            }
        }
    }

    /// Returns whether the currently loaded libseccomp supports this architecture.
    pub fn is_supported(self) -> bool {
        unsafe {
            sys::seccomp_syscall_resolve_name_arch(
                self as u32,
                "read\0".as_ptr() as *const libc::c_char,
            ) >= 0
        }
    }

    /// Get the "native" architecture.
    ///
    /// This returns the `Arch` variant that corresponds to the system architecture (it will NEVER
    /// return `Arch::NATIVE`).
    pub fn native() -> Self {
        // For common architectures, do detection at compile time and avoid calling into libseccomp

        if cfg!(target_arch = "arm") {
            Self::ARM
        } else if cfg!(target_arch = "aarch64") {
            Self::AARCH64
        } else if cfg!(target_arch = "x86") {
            Self::X86
        } else if cfg!(target_arch = "x86_64") {
            Self::X86_64
        } else {
            Self::get_arch(unsafe { sys::seccomp_arch_native() })
                .expect("Unrecognized architecture returned from libseccomp")
        }
    }

    #[inline]
    pub(crate) fn get_arch(arch_raw: u32) -> Option<Self> {
        for arch in ALL_ARCHES.iter().cloned() {
            if arch as u32 == arch_raw {
                return Some(arch);
            }
        }

        None
    }
}

impl fmt::Display for Arch {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::str::FromStr for Arch {
    type Err = ParseArchError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for (i, &arch_name) in ALL_ARCH_NAMES.iter().enumerate() {
            if s.eq_ignore_ascii_case(arch_name) {
                return Ok(ALL_ARCHES[i]);
            }
        }

        Err(ParseArchError(()))
    }
}

/// Represents an error when parsing an `Arch` from a string.
pub struct ParseArchError(());

impl fmt::Debug for ParseArchError {
    #[inline]
    #[allow(deprecated)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;

        f.debug_struct("ParseArchError")
            .field("message", &self.description())
            .finish()
    }
}

impl fmt::Display for ParseArchError {
    #[inline]
    #[allow(deprecated)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;

        f.write_str(self.description())
    }
}

impl std::error::Error for ParseArchError {
    #[inline]
    fn description(&self) -> &str {
        "Unknown architecture"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    #[test]
    fn test_arch_string() {
        for bad_name in [
            "NATIVE",
            "native",
            "NOEXIST",
            "noexist",
            "very-very-very-long-name",
        ]
        .iter()
        {
            Arch::from_str(bad_name).unwrap_err();
        }

        // Sanity checks
        assert_eq!(Arch::from_str("x86").unwrap(), Arch::X86);
        assert_eq!(Arch::from_str("X86").unwrap(), Arch::X86);
        assert_eq!(Arch::from_str("x86_64").unwrap(), Arch::X86_64);

        for &arch in Arch::all().iter() {
            let arch_name = arch.to_string();

            assert_eq!(Arch::from_str(&arch_name).unwrap(), arch);

            assert_eq!(
                Arch::from_str(&arch_name.to_ascii_lowercase()).unwrap(),
                arch
            );
        }
    }

    #[allow(deprecated)]
    #[test]
    fn test_arch_parse_error() {
        use std::error::Error;

        let err = ParseArchError(());

        assert_eq!(err.to_string(), "Unknown architecture");
        assert_eq!(err.description(), "Unknown architecture");

        assert_eq!(
            format!("{:?}", err),
            "ParseArchError { message: \"Unknown architecture\" }"
        );
    }

    #[test]
    fn test_native_arch() {
        let native_arch = Arch::native();
        assert!(Arch::all().contains(&native_arch));

        // Make sure the result matches seccomp_arch_native(). This checks that the special-casing
        // in Arch::native() is working properly.
        assert_eq!(native_arch as u32, unsafe { sys::seccomp_arch_native() });
    }

    #[test]
    fn test_arch_supported() {
        let all_arches = Arch::all();

        assert_eq!(all_arches, &ALL_ARCHES[..all_arches.len()]);

        for arch in all_arches {
            assert!(arch.is_supported());
        }

        for arch in ALL_ARCHES[all_arches.len()..].iter() {
            assert!(!arch.is_supported());
        }
    }

    #[test]
    fn test_get_arch() {
        for &arch in ALL_ARCHES {
            assert_eq!(Arch::get_arch(arch as u32), Some(arch));
        }

        assert_eq!(Arch::get_arch(Arch::NATIVE as u32), None);
    }
}
