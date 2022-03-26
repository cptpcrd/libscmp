use std::fmt;

use crate::sys;

macro_rules! define_arch {
    ($($name:tt,)*) => {
        /// An architecture supported by `libseccomp`.
        #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
        #[non_exhaustive]
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
        // parisc and parisc64 are not supported on libseccomp<2.4.0
        if cfg!(feature = "libseccomp-2-4") {
            // We can assume that we're running on libseccomp v2.4.0+, so parisc and parisc64 must
            // be supported
            debug_assert!(Arch::PARISC.is_supported());
            debug_assert!(Arch::PARISC64.is_supported());
        } else if !Arch::PARISC64.is_supported() {
            // We weren't told we'll be running on v2.4.0+, and parisc64 isn't supported.

            // parisc shouldn't be supported either
            debug_assert!(!Arch::PARISC.is_supported());

            // Cut the list before parisc
            debug_assert_eq!(ALL_ARCHES[16], Arch::PARISC);
            return &ALL_ARCHES[..16];
        }

        // riscv64 is not supported on libseccomp<2.5.0
        if cfg!(feature = "libseccomp-2-5") {
            // We can assume that we're running on libseccomp v2.5.0+, so riscv64 must be supported
            debug_assert!(Arch::RISCV64.is_supported());
        } else if !Arch::RISCV64.is_supported() {
            // We weren't told we'll be running on v2.5.0+, and riscv64 isn't supported.
            debug_assert_eq!(ALL_ARCHES[18], Arch::RISCV64);
            return &ALL_ARCHES[..18];
        }

        // All architectures supported
        ALL_ARCHES
    }

    /// Returns whether the currently loaded libseccomp supports this architecture.
    #[inline]
    pub fn is_supported(self) -> bool {
        unsafe {
            sys::seccomp_syscall_resolve_name_arch(
                self as u32,
                "read\0".as_ptr() as *const libc::c_char,
            ) != sys::NR_SCMP_ERROR
        }
    }

    /// Get the "native" architecture.
    ///
    /// This returns the `Arch` variant that corresponds to the system architecture (it will NEVER
    /// return `Arch::NATIVE`).
    ///
    /// Note that [`Arch::NATIVE`] will often work instead. For example,
    /// `filter.add_arch(Arch::NATIVE)` is equivalent to `filter.add_arch(Arch::native())`. This
    /// function only needs to be used if it is necessary to e.g. print out the name of the native
    /// architecture.
    pub fn native() -> Self {
        // For common architectures, do detection at compile time and avoid calling into libseccomp

        if cfg!(target_arch = "arm") {
            Self::ARM
        } else if cfg!(target_arch = "aarch64") {
            Self::AARCH64
        } else if cfg!(target_arch = "x86") {
            Self::X86
        } else if cfg!(target_arch = "x86_64") {
            if cfg!(target_pointer_width = "64") {
                Self::X86_64
            } else {
                Self::X32
            }
        } else {
            Self::get_arch(unsafe { sys::seccomp_arch_native() })
                .expect("Unrecognized architecture returned from libseccomp")
        }
    }

    #[inline]
    pub(crate) fn get_arch(arch_raw: u32) -> Option<Self> {
        // We can't just transmute() it because it's *possible* that newer versions of libseccomp
        // could return an architecture that we don't know about, and we don't want to accidentally
        // trigger UB. (This search shouldn't be *too* expensive.)

        ALL_ARCHES
            .iter()
            .cloned()
            .find(|&arch| arch as u32 == arch_raw)
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
        for (&arch, &arch_name) in ALL_ARCHES.iter().zip(ALL_ARCH_NAMES.iter()) {
            if s.eq_ignore_ascii_case(arch_name) {
                return Ok(arch);
            }
        }

        Err(ParseArchError(()))
    }
}

/// Represents an error when parsing an `Arch` from a string.
pub struct ParseArchError(());

impl ParseArchError {
    #[inline]
    fn desc(&self) -> &str {
        "Unknown architecture"
    }
}

impl fmt::Debug for ParseArchError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ParseArchError")
            .field("message", &self.desc())
            .finish()
    }
}

impl fmt::Display for ParseArchError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.desc())
    }
}

impl std::error::Error for ParseArchError {}

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
        let err = ParseArchError(());

        assert_eq!(err.to_string(), "Unknown architecture");
        assert_eq!(err.desc(), "Unknown architecture");

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
