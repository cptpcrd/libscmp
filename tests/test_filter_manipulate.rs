use libscmp::{resolve_syscall_name, Action, Arch, Arg, Filter, Flag};

fn arch_nonnative() -> Arch {
    match Arch::native() {
        Arch::X86_64 => Arch::ARM,
        _ => Arch::X86_64,
    }
}

#[test]
fn test_default_action() {
    for action in [
        Action::Allow,
        Action::KillProcess,
        Action::KillThread,
        Action::Log,
        Action::Errno(libc::EPERM),
    ]
    .iter()
    .copied()
    {
        assert_eq!(
            Filter::new(action).unwrap().get_default_action().unwrap(),
            action
        );
    }
}

#[test]
fn test_badarch_action() {
    let mut filter = Filter::new(Action::Allow).unwrap();

    assert_eq!(filter.get_badarch_action().unwrap(), Action::KillThread);

    for action in [
        Action::Allow,
        Action::KillProcess,
        Action::KillThread,
        Action::Log,
        Action::Errno(libc::EPERM),
    ]
    .iter()
    .copied()
    {
        filter.set_badarch_action(action).unwrap();
        assert_eq!(filter.get_badarch_action().unwrap(), action);
    }
}

#[test]
fn test_get_set_flags() {
    let mut filter = Filter::new(Action::Allow).unwrap();

    for flag in [Flag::NoNewPrivs, Flag::SysRawRC, Flag::Log]
        .iter()
        .copied()
    {
        let orig_val = filter.get_flag(flag).unwrap();

        for val in [true, false, orig_val].iter().copied() {
            filter.set_flag(flag, val).unwrap();
            assert_eq!(filter.get_flag(flag).unwrap(), val);
        }
    }
}

#[test]
fn test_has_arches() {
    let filter = Filter::new(Action::Allow).unwrap();

    assert!(filter.has_arch(Arch::NATIVE).unwrap());
    assert!(filter.has_arch(Arch::native()).unwrap());
    assert!(!filter.has_arch(arch_nonnative()).unwrap());
}

#[test]
fn test_add_remove_arches() {
    let mut filter = Filter::new(Action::Allow).unwrap();

    filter.remove_arch(Arch::NATIVE).unwrap();
    filter.add_arch(arch_nonnative()).unwrap();

    assert!(!filter.has_arch(Arch::NATIVE).unwrap());
    assert!(!filter.has_arch(Arch::native()).unwrap());
    assert!(filter.has_arch(arch_nonnative()).unwrap());

    assert_eq!(
        filter.remove_arch(Arch::NATIVE).unwrap_err().raw_os_error(),
        Some(libc::ENOENT)
    );
    assert_eq!(
        filter
            .remove_arch(Arch::native())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    assert_eq!(
        filter
            .add_arch(arch_nonnative())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EEXIST)
    );
}

#[test]
fn test_reset() {
    let mut filter = Filter::new(Action::Allow).unwrap();

    filter.remove_arch(Arch::NATIVE).unwrap();
    filter.add_arch(arch_nonnative()).unwrap();

    assert!(!filter.has_arch(Arch::NATIVE).unwrap());
    assert!(!filter.has_arch(Arch::native()).unwrap());
    assert!(filter.has_arch(arch_nonnative()).unwrap());

    filter.reset(Action::Allow).unwrap();

    assert!(filter.has_arch(Arch::NATIVE).unwrap());
    assert!(filter.has_arch(Arch::native()).unwrap());
    assert!(!filter.has_arch(arch_nonnative()).unwrap());
}

#[test]
fn test_syscall_priority() {
    let mut filter = Filter::new(Action::Allow).unwrap();

    filter
        .syscall_priority(resolve_syscall_name("exit").unwrap(), 255)
        .unwrap();

    assert_eq!(
        filter.syscall_priority(-1, 255).unwrap_err().raw_os_error(),
        Some(libc::EINVAL)
    );
}

#[test]
fn test_bad_add_rule() {
    let mut filter = Filter::new(Action::Allow).unwrap();

    // Trying to match on the "6th" syscall argument (does not exist) will fail with EINVAL.

    assert_eq!(
        filter
            .add_rule(
                Action::KillProcess,
                resolve_syscall_name("setpriority").unwrap(),
                &[Arg::new_eq(6, 0)]
            )
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EINVAL)
    );
}

#[test]
fn test_bad_merge() {
    let mut filter = Filter::new(Action::Allow).unwrap();

    assert_eq!(
        filter
            .merge(Filter::new(Action::Allow).unwrap())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EEXIST)
    );
}
