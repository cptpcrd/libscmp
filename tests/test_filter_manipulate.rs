use libscmp::{resolve_syscall_name, Action, Arch, Arg, Filter, Flag};

fn arch_nonnative() -> Arch {
    match Arch::native() {
        Arch::X86_64 => Arch::ARM,
        _ => Arch::X86_64,
    }
}

fn get_actions() -> Vec<(Action, bool)> {
    let ver = libscmp::libseccomp_version();

    vec![
        (Action::Allow, true),
        (Action::KillThread, true),
        (Action::Errno(libc::EPERM), true),
        (Action::Trap, true),
        (Action::Trace(1), true),
        (Action::KillProcess, ver >= (2, 4, 0)),
        (Action::Log, ver >= (2, 4, 0)),
        (Action::Notify, ver >= (2, 5, 0)),
    ]
}

#[test]
fn test_default_action() {
    for (action, supported) in get_actions().iter().copied() {
        if supported {
            assert_eq!(
                Filter::new(action).unwrap().get_default_action().unwrap(),
                action
            );

            let mut filter = Filter::new(Action::KillThread).unwrap();
            filter.reset(action).unwrap();
            assert_eq!(filter.get_default_action().unwrap(), action);
        } else {
            assert_eq!(Filter::new(action).unwrap_err().code(), libc::EINVAL);

            let mut filter = Filter::new(Action::KillThread).unwrap();
            assert_eq!(filter.reset(action).unwrap_err().code(), libc::EINVAL);
        }
    }
}

#[test]
fn test_badarch_action() {
    let mut filter = Filter::new(Action::Allow).unwrap();

    assert_eq!(filter.get_badarch_action().unwrap(), Action::KillThread);

    for (action, supported) in get_actions().iter().copied() {
        if supported {
            filter.set_badarch_action(action).unwrap();
            assert_eq!(filter.get_badarch_action().unwrap(), action);
        } else {
            assert_eq!(
                filter.set_badarch_action(action).unwrap_err().code(),
                libc::EINVAL
            );
        }
    }
}

#[test]
fn test_get_set_flags() {
    let mut filter = Filter::new(Action::Allow).unwrap();

    let version = libscmp::libseccomp_version();

    let flags = if version >= (2, 5, 0) {
        &[Flag::NoNewPrivs, Flag::Log, Flag::SysRawRC][..]
    } else if version >= (2, 4, 0) {
        &[Flag::NoNewPrivs, Flag::Log][..]
    } else {
        &[Flag::NoNewPrivs][..]
    };

    for flag in flags.iter().copied() {
        let orig_val = filter.get_flag(flag).unwrap();

        for val in [true, false, orig_val].iter().copied() {
            filter.set_flag(flag, val).unwrap();
            assert_eq!(filter.get_flag(flag).unwrap(), val);
        }
    }
}

#[test]
fn test_optimize_level() {
    if libscmp::libseccomp_version() >= (2, 5, 0) {
        let mut filter = Filter::new(Action::Allow).unwrap();

        assert_eq!(filter.get_optimize_level().unwrap(), 1);

        filter.set_optimize_level(2).unwrap();
        assert_eq!(filter.get_optimize_level().unwrap(), 2);

        filter.set_optimize_level(1).unwrap();
        assert_eq!(filter.get_optimize_level().unwrap(), 1);
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
        filter.remove_arch(Arch::NATIVE).unwrap_err().code(),
        libc::ENOENT
    );
    assert_eq!(
        filter.remove_arch(Arch::native()).unwrap_err().code(),
        libc::ENOENT
    );
    assert_eq!(
        filter.add_arch(arch_nonnative()).unwrap_err().code(),
        libc::EEXIST
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
        filter.syscall_priority(-1, 255).unwrap_err().code(),
        libc::EINVAL
    );
}

#[test]
fn test_bad_add_rule() {
    let mut filter = Filter::new(Action::Allow).unwrap();

    // Trying to match on the "6th" syscall argument (does not exist) will fail with EINVAL.

    assert_eq!(
        filter
            .add_rule(
                Action::KillThread,
                resolve_syscall_name("setpriority").unwrap(),
                &[Arg::new_eq(6, 0)]
            )
            .unwrap_err()
            .code(),
        libc::EINVAL
    );
}

#[test]
fn test_bad_merge() {
    let mut filter = Filter::new(Action::Allow).unwrap();

    assert_eq!(
        filter
            .merge(Filter::new(Action::Allow).unwrap())
            .unwrap_err()
            .code(),
        libc::EEXIST
    );
}
