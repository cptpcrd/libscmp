use std::ffi::{CStr, CString, OsStr, OsString};
use std::io;
use std::os::unix::prelude::*;
use std::ptr::NonNull;

mod arch;
mod sys;

pub use arch::{Arch, ParseArchError};

/// Specifies an action to be taken, either as the default action for a filter or when a rule
/// matches.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Action {
    KillProcess,
    KillThread,
    Trap,
    Notify,
    Log,
    Allow,
    Errno(libc::c_int),
    Trace(u16),
}

impl Action {
    fn to_raw(self) -> u32 {
        match self {
            Self::KillProcess => sys::SCMP_ACT_KILL_PROCESS,
            Self::KillThread => sys::SCMP_ACT_KILL,
            Self::Trap => sys::SCMP_ACT_TRAP,
            Self::Notify => sys::SCMP_ACT_NOTIFY,
            Self::Log => sys::SCMP_ACT_LOG,
            Self::Allow => sys::SCMP_ACT_ALLOW,
            Self::Errno(eno) => sys::SCMP_ACT_ERRNO(eno as u16),
            Self::Trace(msg_num) => sys::SCMP_ACT_TRACE(msg_num),
        }
    }

    fn from_raw(val: u32) -> Option<Self> {
        match val & sys::SCMP_ACT_MASK {
            sys::SCMP_ACT_KILL_PROCESS => Some(Self::KillProcess),
            sys::SCMP_ACT_KILL => Some(Self::KillThread),
            sys::SCMP_ACT_TRAP => Some(Self::Trap),
            sys::SCMP_ACT_NOTIFY => Some(Self::Notify),
            sys::SCMP_ACT_LOG => Some(Self::Log),
            sys::SCMP_ACT_ALLOW => Some(Self::Allow),
            sys::SCMP_ACT_ERRNO_MASK => Some(Self::Errno(val as u16 as libc::c_int)),
            sys::SCMP_ACT_TRACE_MASK => Some(Self::Trace(val as u16)),
            _ => None,
        }
    }
}

// Technically, Cmp and Flag should be `repr(libc::c_int)`, but Rust doesn't let you do that.
// However, libc::c_int should be i32 on all platforms. Additionally, the constants are declared as
// libc::c_int, so it won't compile if there's a mismatch.

/// Represents a comparison type that can be used in an [`Arg`](./struct.Arg.html).
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum Cmp {
    Ne = sys::SCMP_CMP_NE,
    Lt = sys::SCMP_CMP_LT,
    Le = sys::SCMP_CMP_LE,
    Eq = sys::SCMP_CMP_EQ,
    Ge = sys::SCMP_CMP_GE,
    Gt = sys::SCMP_CMP_GT,
    MaskedEq = sys::SCMP_CMP_MASKED_EQ,
}

/// Represents a boolean flag that can be set on a filter.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum Flag {
    /// Whether `libseccomp` should enable the "no-new-privs" mechanism before loading the seccomp
    /// filter (default `true`).
    ///
    /// In most cases, this should be set to `true`.
    NoNewPrivs = sys::SCMP_FLTATR_CTL_NNP,
    /// Whether the kernel should attempt to synchronize the seccomp filters across all threads
    /// when loading them into the kernel (default `false`).
    ///
    /// This is only supported on Linux 3.17+, and it may cause loading the seccomp filters to
    /// fail.
    Tsync = sys::SCMP_FLTATR_CTL_TSYNC,
    /// Whether `libseccomp` should allow filter rules that target the -1 syscall (sometimes used
    /// by ptrace()rs to skip syscalls). Defaults to `false`.
    Tskip = sys::SCMP_FLTATR_API_TSKIP,
    /// Whether the kernel should log all non-"allow" actions taken (default `false`).
    Log = sys::SCMP_FLTATR_CTL_LOG,
    /// Whether to disable Speculative Store Bypass mitigation for this filter (default `false`).
    DisableSSB = sys::SCMP_FLTATR_CTL_SSB,
    /// Whether `libseccomp` should pass system error codes back to the caller instead of returning
    /// `ECANCELED` (default `false`).
    SysRawRC = sys::SCMP_FLTATR_API_SYSRAWRC,
}

/// Represents a syscall argument comparison, used in a filter rule.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct Arg {
    arg: libc::c_uint,
    op: Cmp,
    data_a: u64,
    data_b: u64,
}

impl Arg {
    /// Create a syscall argument comparison given the argument number, comparison operator, and
    /// two data arguments.
    ///
    /// For example, `Arg::new(1, Cmp::EQ, 2, 0)` is equivalent to `Arg::new_eq(1, 2)`, and
    /// `Arg::new(0, Cmp::MASKED_EQ, 1, 2)` is equivalent to `Arg::new_masked_eq(0, 1, 2)`.
    #[inline]
    pub fn new(arg: libc::c_uint, op: Cmp, data_a: u64, data_b: u64) -> Self {
        Self {
            arg,
            op,
            data_a,
            data_b,
        }
    }

    /// Create a syscall argument comparison that filters for the given argument being **not equal
    /// to** the given value.
    ///
    /// Essentially, this filters for `SYSCALL_ARGS[arg] != data`.
    #[inline]
    pub fn new_ne(arg: libc::c_uint, data: u64) -> Self {
        Self::new(arg, Cmp::Ne, data, 0)
    }

    /// Create a syscall argument comparison that filters for the given argument being **less than**
    /// the given value.
    ///
    /// Essentially, this filters for `SYSCALL_ARGS[arg] < data`.
    #[inline]
    pub fn new_lt(arg: libc::c_uint, data: u64) -> Self {
        Self::new(arg, Cmp::Lt, data, 0)
    }

    /// Create a syscall argument comparison that filters for the given argument being **less than
    /// or equal to** the given value.
    ///
    /// Essentially, this filters for `SYSCALL_ARGS[arg] <= data`.
    #[inline]
    #[inline]
    pub fn new_le(arg: libc::c_uint, data: u64) -> Self {
        Self::new(arg, Cmp::Le, data, 0)
    }

    /// Create a syscall argument comparison that filters for the given argument being **equal to**
    /// the given value.
    ///
    /// Essentially, this filters for `SYSCALL_ARGS[arg] == data`.
    #[inline]
    pub fn new_eq(arg: libc::c_uint, data: u64) -> Self {
        Self::new(arg, Cmp::Eq, data, 0)
    }

    /// Create a syscall argument comparison that filters for the given argument being **greater
    /// than or equal to** the given value.
    ///
    /// Essentially, this filters for `SYSCALL_ARGS[arg] >= data`.
    #[inline]
    pub fn new_ge(arg: libc::c_uint, data: u64) -> Self {
        Self::new(arg, Cmp::Ge, data, 0)
    }

    /// Create a syscall argument comparison that filters for the given argument being **greater
    /// than** the given value.
    ///
    /// Essentially, this filters for `SYSCALL_ARGS[arg] > data`.
    #[inline]
    pub fn new_gt(arg: libc::c_uint, data: u64) -> Self {
        Self::new(arg, Cmp::Gt, data, 0)
    }

    /// Create a syscall argument comparison that filters for the given argument being **equal to**
    /// the given value, once the specified `mask` is applied.
    ///
    /// Essentially, this filters for `SYSCALL_ARGS[arg] & mask == data`.
    #[inline]
    pub fn new_masked_eq(arg: libc::c_uint, mask: u64, data: u64) -> Self {
        Self::new(arg, Cmp::MaskedEq, mask, data)
    }
}

/// Represents a syscall filter.
#[derive(Debug)]
pub struct Filter {
    ctx: NonNull<libc::c_void>,
}

impl Filter {
    /// Create a new seccomp filter with the given default action.
    #[inline]
    pub fn new(def_action: Action) -> io::Result<Self> {
        match NonNull::new(unsafe { sys::seccomp_init(def_action.to_raw()) }) {
            Some(ctx) => Ok(Self { ctx }),
            None => Err(io::Error::from_raw_os_error(libc::EINVAL)),
        }
    }

    /// Re-initialize this seccomp filter with the given default action.
    #[inline]
    pub fn reset(&mut self, def_action: Action) -> io::Result<()> {
        check_status(unsafe { sys::seccomp_reset(self.ctx.as_ptr(), def_action.to_raw()) })
    }

    /// Merge another seccomp filter into this one.
    ///
    /// See seccomp_merge(3) for more details.
    #[inline]
    pub fn merge(&mut self, other: Self) -> io::Result<()> {
        check_status(unsafe { sys::seccomp_merge(self.ctx.as_ptr(), other.ctx.as_ptr()) })?;
        std::mem::forget(other);
        Ok(())
    }

    /// Load the syscall filter rules into the kernel.
    #[inline]
    pub fn load(&mut self) -> io::Result<()> {
        check_status(unsafe { sys::seccomp_load(self.ctx.as_ptr()) })
    }

    /// Export this filter as BPF (Berkeley Packet Filter) code to the file with the specified file
    /// descriptor.
    ///
    /// See seccomp_export_bpf(3) for more details.
    #[inline]
    pub fn export_bpf(&self, fd: RawFd) -> io::Result<()> {
        check_status(unsafe { sys::seccomp_export_bpf(self.ctx.as_ptr(), fd) })
    }

    /// Export this filter as PFC (Pseudo Filter Code) code to the file with the specified file
    /// descriptor.
    ///
    /// See seccomp_export_pfc(3) for more details.
    #[inline]
    pub fn export_pfc(&self, fd: RawFd) -> io::Result<()> {
        check_status(unsafe { sys::seccomp_export_pfc(self.ctx.as_ptr(), fd) })
    }

    /// Add the given architecture to the filter,
    ///
    /// See seccomp_arch_add(3) for details.
    #[inline]
    pub fn add_arch(&mut self, arch: Arch) -> io::Result<()> {
        check_status(unsafe { sys::seccomp_arch_add(self.ctx.as_ptr(), arch as u32) })
    }

    /// Remove the given architecture from the filter,
    ///
    /// See seccomp_arch_remove(3) for details.
    #[inline]
    pub fn remove_arch(&mut self, arch: Arch) -> io::Result<()> {
        match -unsafe { sys::seccomp_arch_remove(self.ctx.as_ptr(), arch as u32) } {
            0 => Ok(()),
            libc::EEXIST => Err(io::Error::from_raw_os_error(libc::ENOENT)),
            ret => {
                debug_assert!(ret > 0);
                Err(io::Error::from_raw_os_error(ret))
            }
        }
    }

    /// Check if the given architecture has been added to the filter.
    ///
    /// See seccomp_arch_exist(3) for details.
    pub fn has_arch(&self, arch: Arch) -> io::Result<bool> {
        match -unsafe { sys::seccomp_arch_exist(self.ctx.as_ptr(), arch as u32) } {
            0 => Ok(true),
            libc::EEXIST => Ok(false),
            ret => {
                debug_assert!(ret > 0);
                Err(io::Error::from_raw_os_error(ret))
            }
        }
    }

    /// Prioritize the given syscall in this filter.
    ///
    /// This provides a hint to the seccomp filter generator that the given syscall should be
    /// prioritized and placed earlier in the filter code. Higher `priority` values represent
    /// higher priorities.
    ///
    /// See seccomp_syscall_priority(3) for details.
    #[inline]
    pub fn syscall_priority(&mut self, syscall: libc::c_int, priority: u8) -> io::Result<()> {
        check_status(unsafe { sys::seccomp_syscall_priority(self.ctx.as_ptr(), syscall, priority) })
    }

    /// Add a new rule to this filter.
    ///
    /// `action` specifies the action to take if the filter matches, `syscall` specifies the system
    /// call number which should be matched against, and `args` is a list of syscall argument
    /// comparisons to use to match the syscall's arguments.
    ///
    /// This function may alter the rule slightly depending on architecture-specific semantics. To add the
    /// rule with no changes, see [`add_rule_exact()`](#method.add_rule_exact).
    #[inline]
    pub fn add_rule(
        &mut self,
        action: Action,
        syscall: libc::c_int,
        args: &[Arg],
    ) -> io::Result<()> {
        check_status(unsafe {
            sys::seccomp_rule_add_array(
                self.ctx.as_ptr(),
                action.to_raw(),
                syscall,
                args.len() as libc::c_uint,
                args.as_ptr() as *const sys::scmp_arg_cmp,
            )
        })
    }

    /// Add a new rule to this filter, without any per-architecture modifications.
    ///
    /// Other than the lack of per-architecture modifications, this is exactly equivalent to
    /// [`add_rule()`](#method.add_rule).
    #[inline]
    pub fn add_rule_exact(
        &mut self,
        action: Action,
        syscall: libc::c_int,
        args: &[Arg],
    ) -> io::Result<()> {
        check_status(unsafe {
            sys::seccomp_rule_add_exact_array(
                self.ctx.as_ptr(),
                action.to_raw(),
                syscall,
                args.len() as libc::c_uint,
                args.as_ptr() as *const sys::scmp_arg_cmp,
            )
        })
    }

    #[inline]
    fn get_attr(&mut self, attr: libc::c_int) -> io::Result<u32> {
        let mut res = 0;
        check_status(unsafe { sys::seccomp_attr_get(self.ctx.as_ptr(), attr, &mut res) })?;
        Ok(res)
    }

    #[inline]
    fn set_attr(&mut self, attr: libc::c_int, value: u32) -> io::Result<()> {
        check_status(unsafe { sys::seccomp_attr_set(self.ctx.as_ptr(), attr, value) })
    }

    /// Get the default filter action (as set when the filter was created or reset).
    #[inline]
    pub fn get_default_action(&mut self) -> io::Result<Action> {
        Action::from_raw(self.get_attr(sys::SCMP_FLTATR_ACT_DEFAULT)?)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))
    }

    /// Get the action taken when the loaded filter does not match the application's architecture
    /// (defaults to `KillThread`).
    #[inline]
    pub fn get_badarch_action(&mut self) -> io::Result<Action> {
        Action::from_raw(self.get_attr(sys::SCMP_FLTATR_ACT_BADARCH)?)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))
    }

    /// Set the action taken when the loaded filter does not match the application's architecture.
    #[inline]
    pub fn set_badarch_action(&mut self, act: Action) -> io::Result<()> {
        self.set_attr(sys::SCMP_FLTATR_ACT_BADARCH, act.to_raw())
    }

    /// Get the value of the given flag in this filter.
    ///
    /// See [`Flag`](./enum.Flag.html) for more details.
    #[inline]
    pub fn get_flag(&mut self, flag: Flag) -> io::Result<bool> {
        Ok(self.get_attr(flag as libc::c_int)? != 0)
    }

    /// Set the value of the given flag in this filter.
    ///
    /// See [`Flag`](./enum.Flag.html) for more details.
    #[inline]
    pub fn set_flag(&mut self, flag: Flag, val: bool) -> io::Result<()> {
        self.set_attr(flag as libc::c_int, val as u32)
    }

    /// Get the current optimization level of the filter.
    ///
    /// See seccomp_attr_get(3) for more information.
    #[inline]
    pub fn get_optimize_level(&mut self) -> io::Result<u32> {
        self.get_attr(sys::SCMP_FLTATR_CTL_OPTIMIZE)
    }

    /// Set the optimization level of the filter.
    ///
    /// See seccomp_attr_get(3) for more information.
    #[inline]
    pub fn set_optimize_level(&mut self, level: u32) -> io::Result<()> {
        self.set_attr(sys::SCMP_FLTATR_CTL_OPTIMIZE, level)
    }
}

impl Drop for Filter {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            sys::seccomp_release(self.ctx.as_ptr());
        }
    }
}

fn check_status(ret: libc::c_int) -> io::Result<()> {
    if ret == 0 {
        Ok(())
    } else {
        debug_assert!(ret < 0);
        Err(io::Error::from_raw_os_error(-ret))
    }
}

/// Look up the name of a syscall given the architecture and the syscall number.
pub fn resolve_syscall_num(arch: Arch, num: libc::c_int) -> Option<OsString> {
    let ptr = unsafe { sys::seccomp_syscall_resolve_num_arch(arch as u32, num) };

    if ptr.is_null() {
        return None;
    }

    let s = OsStr::from_bytes(unsafe { CStr::from_ptr(ptr) }.to_bytes()).to_os_string();

    unsafe {
        libc::free(ptr as *mut libc::c_void);
    }

    Some(s)
}

/// Look up the number of the syscall with the given name on the native architecture.
///
/// This is exactly equivalent to `resolve_syscall_name_arch(Arch::NATIVE, name)` (or
/// `resolve_syscall_name_arch(Arch::native(), name)`).
#[inline]
pub fn resolve_syscall_name<N: AsRef<OsStr>>(name: N) -> Option<libc::c_int> {
    resolve_syscall_name_arch(Arch::NATIVE, name)
}

/// Look up the number of the syscall with the given name on the given architecture.
#[inline]
pub fn resolve_syscall_name_arch<N: AsRef<OsStr>>(arch: Arch, name: N) -> Option<libc::c_int> {
    fn inner(arch: Arch, name: &OsStr) -> Option<libc::c_int> {
        let c_name = CString::new(name.as_bytes()).ok()?;

        match unsafe { sys::seccomp_syscall_resolve_name_arch(arch as u32, c_name.as_ptr()) } {
            sys::NR_SCMP_ERROR => None,
            nr => Some(nr),
        }
    }

    inner(arch, name.as_ref())
}

/// Look up the number of the syscall with the given name on the given architecture, modifying the
/// syscall number for multiplexed syscalls.
#[inline]
pub fn resolve_syscall_name_rewrite<N: AsRef<OsStr>>(arch: Arch, name: N) -> Option<libc::c_int> {
    fn inner(arch: Arch, name: &OsStr) -> Option<libc::c_int> {
        let c_name = CString::new(name.as_bytes()).ok()?;

        match unsafe { sys::seccomp_syscall_resolve_name_rewrite(arch as u32, c_name.as_ptr()) } {
            sys::NR_SCMP_ERROR => None,
            nr => Some(nr),
        }
    }

    inner(arch, name.as_ref())
}

/// Get the "API level" supported by the running kernel.
///
/// See seccomp_api_get(3) for details.
///
/// Note: This is only available with the `libseccomp-2-4` feature.
#[cfg(feature = "libseccomp-2-4")]
#[inline]
pub fn api_get() -> libc::c_uint {
    unsafe { sys::seccomp_api_get() }
}

/// Force the API level used by libseccomp (do not use unless you know what you're doing).
///
/// See seccomp_api_set(3) for details.
///
/// Note: This is only available with the `libseccomp-2-4` feature.
#[cfg(feature = "libseccomp-2-4")]
#[inline]
pub fn api_set(level: libc::c_uint) -> io::Result<()> {
    check_status(unsafe { sys::seccomp_api_set(level) })
}

/// Get the version of the currently loaded `libseccomp` library.
///
/// The version is returned as a `(major, minor, micro)` tuple; for example `(2, 4, 3)`.
pub fn libseccomp_version() -> (libc::c_uint, libc::c_uint, libc::c_uint) {
    // It *shouldn't* return NULL. However, the man page mentions it as a possibility, so let's be
    // cautious and panic instead of segfaulting if that happens.
    let ver = unsafe { sys::seccomp_version().as_ref().unwrap() };

    (ver.major, ver.minor, ver.micro)
}

/// Reset `libseccomp`'s global state.
///
/// See seccomp_reset(3) for more details (specifically, the description of what happens if the
/// specified filter is NULL).
pub fn reset_global_state() -> io::Result<()> {
    check_status(unsafe { sys::seccomp_reset(std::ptr::null_mut(), 0) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arg_new() {
        assert_eq!(Arg::new(1, Cmp::Ne, 2, 0), Arg::new_ne(1, 2));
        assert_eq!(Arg::new(1, Cmp::Lt, 2, 0), Arg::new_lt(1, 2));
        assert_eq!(Arg::new(1, Cmp::Le, 2, 0), Arg::new_le(1, 2));
        assert_eq!(Arg::new(1, Cmp::Eq, 2, 0), Arg::new_eq(1, 2));
        assert_eq!(Arg::new(1, Cmp::Ge, 2, 0), Arg::new_ge(1, 2));
        assert_eq!(Arg::new(1, Cmp::Gt, 2, 0), Arg::new_gt(1, 2));
        assert_eq!(
            Arg::new(1, Cmp::MaskedEq, !0o777, 0),
            Arg::new_masked_eq(1, !0o777, 0)
        );
    }

    #[test]
    fn test_resolve_syscall() {
        assert_eq!(
            resolve_syscall_num(Arch::NATIVE, resolve_syscall_name("read").unwrap()).unwrap(),
            "read"
        );

        assert_eq!(
            resolve_syscall_name("read").unwrap(),
            resolve_syscall_name_rewrite(Arch::NATIVE, "read").unwrap(),
        );

        assert_eq!(resolve_syscall_name("NOSYSCALL"), None);
        assert_eq!(resolve_syscall_name("read\0"), None);
        assert_eq!(
            resolve_syscall_name_rewrite(Arch::NATIVE, "NOSYSCALL"),
            None
        );
        assert_eq!(resolve_syscall_num(Arch::NATIVE, -1), None);

        assert_eq!(
            resolve_syscall_name_rewrite(Arch::X86, "socketcall").unwrap(),
            resolve_syscall_name_rewrite(Arch::X86, "socket").unwrap(),
        );
    }

    #[test]
    fn test_check_status() {
        check_status(0).unwrap();
        assert_eq!(
            check_status(-libc::EEXIST).unwrap_err().raw_os_error(),
            Some(libc::EEXIST)
        );
    }

    #[test]
    fn test_version() {
        assert!(libseccomp_version() >= (2, 3, 0));

        #[cfg(feature = "libseccomp-2-4")]
        assert!(libseccomp_version() >= (2, 4, 0));
    }
}
