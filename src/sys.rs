// In some cases, we preserve the names directly from libseccomp, so they don't match convention
#![allow(non_snake_case)]

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct scmp_arg_cmp {
    pub arg: libc::c_uint,
    pub op: libc::c_int,
    pub datum_a: u64,
    pub datum_b: u64,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct scmp_version {
    pub major: libc::c_uint,
    pub minor: libc::c_uint,
    pub micro: libc::c_uint,
}

#[cfg(feature = "libseccomp-2-5")]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct seccomp_data {
    pub nr: libc::c_int,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[cfg(feature = "libseccomp-2-5")]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct seccomp_notif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: seccomp_data,
}

#[cfg(feature = "libseccomp-2-5")]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct seccomp_notif_resp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

pub const SCMP_CMP_NE: libc::c_int = 1;
pub const SCMP_CMP_LT: libc::c_int = 2;
pub const SCMP_CMP_LE: libc::c_int = 3;
pub const SCMP_CMP_EQ: libc::c_int = 4;
pub const SCMP_CMP_GE: libc::c_int = 5;
pub const SCMP_CMP_GT: libc::c_int = 6;
pub const SCMP_CMP_MASKED_EQ: libc::c_int = 7;

extern "C" {
    pub fn seccomp_init(def_action: u32) -> *mut libc::c_void;
    pub fn seccomp_reset(ctx: *mut libc::c_void, def_action: u32) -> libc::c_int;

    pub fn seccomp_merge(dst: *mut libc::c_void, src: *mut libc::c_void) -> libc::c_int;

    pub fn seccomp_release(ctx: *mut libc::c_void);

    pub fn seccomp_load(ctx: *mut libc::c_void) -> libc::c_int;

    pub fn seccomp_export_bpf(ctx: *mut libc::c_void, fd: libc::c_int) -> libc::c_int;
    pub fn seccomp_export_pfc(ctx: *mut libc::c_void, fd: libc::c_int) -> libc::c_int;

    pub fn seccomp_arch_add(ctx: *mut libc::c_void, arch_token: u32) -> libc::c_int;
    pub fn seccomp_arch_remove(ctx: *mut libc::c_void, arch_token: u32) -> libc::c_int;
    pub fn seccomp_arch_exist(ctx: *const libc::c_void, arch_token: u32) -> libc::c_int;

    pub fn seccomp_syscall_priority(
        ctx: *mut libc::c_void,
        syscall: libc::c_int,
        priority: u8,
    ) -> libc::c_int;

    pub fn seccomp_attr_set(ctx: *mut libc::c_void, attr: libc::c_int, value: u32) -> libc::c_int;
    pub fn seccomp_attr_get(
        ctx: *const libc::c_void,
        attr: libc::c_int,
        value: *mut u32,
    ) -> libc::c_int;

    pub fn seccomp_rule_add_array(
        ctx: *mut libc::c_void,
        action: u32,
        syscall: libc::c_int,
        arg_cnt: libc::c_uint,
        arg_array: *const scmp_arg_cmp,
    ) -> libc::c_int;
    pub fn seccomp_rule_add_exact_array(
        ctx: *mut libc::c_void,
        action: u32,
        syscall: libc::c_int,
        arg_cnt: libc::c_uint,
        arg_array: *const scmp_arg_cmp,
    ) -> libc::c_int;

    pub fn seccomp_syscall_resolve_num_arch(arch: u32, num: libc::c_int) -> *mut libc::c_char;
    pub fn seccomp_syscall_resolve_name_arch(arch: u32, name: *const libc::c_char) -> libc::c_int;
    pub fn seccomp_syscall_resolve_name_rewrite(
        arch: u32,
        name: *const libc::c_char,
    ) -> libc::c_int;

    pub fn seccomp_arch_native() -> u32;

    pub fn seccomp_version() -> *const scmp_version;

    #[cfg(feature = "libseccomp-2-4")]
    pub fn seccomp_api_get() -> libc::c_uint;
    #[cfg(feature = "libseccomp-2-4")]
    pub fn seccomp_api_set(level: libc::c_uint) -> libc::c_int;
}

#[cfg(feature = "libseccomp-2-5")]
extern "C" {
    pub fn seccomp_notify_alloc(
        req: *mut *mut seccomp_notif,
        resp: *mut *mut seccomp_notif_resp,
    ) -> libc::c_int;
    pub fn seccomp_notify_free(req: *mut seccomp_notif, resp: *mut seccomp_notif_resp);

    pub fn seccomp_notify_receive(fd: libc::c_int, req: *mut seccomp_notif) -> libc::c_int;
    pub fn seccomp_notify_respond(fd: libc::c_int, resp: *mut seccomp_notif_resp) -> libc::c_int;

    pub fn seccomp_notify_id_valid(fd: libc::c_int, id: u64) -> libc::c_int;
    pub fn seccomp_notify_fd(ctx: *const libc::c_void) -> libc::c_int;
}

pub const SCMP_ACT_MASK: u32 = 0xFFFF0000;

pub const SCMP_ACT_KILL_PROCESS: u32 = 0x80000000;
pub const SCMP_ACT_KILL: u32 = 0x00000000;
pub const SCMP_ACT_TRAP: u32 = 0x00030000;
pub const SCMP_ACT_NOTIFY: u32 = 0x7FC00000;
pub const SCMP_ACT_LOG: u32 = 0x7FFC0000;
pub const SCMP_ACT_ALLOW: u32 = 0x7FFF0000;

pub const SCMP_ACT_ERRNO_MASK: u32 = 0x00050000;
pub const SCMP_ACT_TRACE_MASK: u32 = 0x7ff00000;

#[inline]
pub const fn SCMP_ACT_ERRNO(eno: u16) -> u32 {
    SCMP_ACT_ERRNO_MASK | (eno as u32)
}

#[inline]
pub const fn SCMP_ACT_TRACE(msg_num: u16) -> u32 {
    SCMP_ACT_TRACE_MASK | (msg_num as u32)
}

// These are in a module instead of as separate constants so the macro that defines the Arch enum
// can easily access them without having to concatenate identifiers.
pub mod SCMP_ARCH {
    const EM_386: u32 = 3;
    const EM_MIPS: u32 = 8;
    const EM_PARISC: u32 = 15;
    const EM_PPC: u32 = 20;
    const EM_PPC64: u32 = 21;
    const EM_S390: u32 = 22;
    const EM_ARM: u32 = 40;
    const EM_X86_64: u32 = 62;
    const EM_AARCH64: u32 = 183;
    const EM_RISCV: u32 = 243;

    const __AUDIT_ARCH_LE: u32 = 0x4000_0000;
    const __AUDIT_ARCH_64BIT: u32 = 0x8000_0000;
    const __AUDIT_ARCH_CONVENTION_MIPS64_N32: u32 = 0x2000_0000;

    pub const NATIVE: u32 = 0;

    pub const X86: u32 = EM_386 | __AUDIT_ARCH_LE;
    pub const X86_64: u32 = EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE;
    pub const X32: u32 = EM_X86_64 | __AUDIT_ARCH_LE;

    pub const ARM: u32 = EM_ARM | __AUDIT_ARCH_LE;
    pub const AARCH64: u32 = EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE;

    pub const MIPS: u32 = EM_MIPS;
    pub const MIPS64: u32 = EM_MIPS | __AUDIT_ARCH_64BIT;
    pub const MIPS64N32: u32 = EM_MIPS | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_CONVENTION_MIPS64_N32;

    pub const MIPSEL: u32 = EM_MIPS | __AUDIT_ARCH_LE;
    pub const MIPSEL64: u32 = EM_MIPS | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE;
    pub const MIPSEL64N32: u32 =
        EM_MIPS | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE | __AUDIT_ARCH_CONVENTION_MIPS64_N32;

    pub const PPC: u32 = EM_PPC;
    pub const PPC64: u32 = EM_PPC64 | __AUDIT_ARCH_64BIT;
    pub const PPC64LE: u32 = EM_PPC64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE;

    pub const S390: u32 = EM_S390;
    pub const S390X: u32 = EM_S390 | __AUDIT_ARCH_64BIT;

    pub const PARISC: u32 = EM_PARISC;
    pub const PARISC64: u32 = EM_PARISC | __AUDIT_ARCH_64BIT;

    pub const RISCV64: u32 = EM_RISCV | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE;
}

pub const NR_SCMP_ERROR: libc::c_int = -1;

pub const SCMP_FLTATR_ACT_DEFAULT: libc::c_int = 1;
pub const SCMP_FLTATR_ACT_BADARCH: libc::c_int = 2;
pub const SCMP_FLTATR_CTL_NNP: libc::c_int = 3;
pub const SCMP_FLTATR_CTL_TSYNC: libc::c_int = 4;
pub const SCMP_FLTATR_API_TSKIP: libc::c_int = 5;
pub const SCMP_FLTATR_CTL_LOG: libc::c_int = 6;
pub const SCMP_FLTATR_CTL_SSB: libc::c_int = 7;
pub const SCMP_FLTATR_CTL_OPTIMIZE: libc::c_int = 8;
pub const SCMP_FLTATR_API_SYSRAWRC: libc::c_int = 9;
