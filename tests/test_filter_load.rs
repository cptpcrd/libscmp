use std::io;

use libscmp::{resolve_syscall_name, Action, Arch, Arg, Filter};

fn arch_nonnative() -> Arch {
    match Arch::native() {
        Arch::X86_64 => Arch::ARM,
        _ => Arch::X86_64,
    }
}

fn getprio(pid: libc::pid_t) -> io::Result<libc::c_int> {
    unsafe {
        *libc::__errno_location() = 0;
    }

    match unsafe { libc::getpriority(0, pid as libc::id_t) } {
        -1 => {
            let err = io::Error::last_os_error();

            if err.raw_os_error() == Some(0) {
                Ok(-1)
            } else {
                Err(err)
            }
        }

        res => Ok(res),
    }
}

fn setprio(value: libc::c_int) -> io::Result<()> {
    if unsafe { libc::setpriority(0, 0, value) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn fork_and_check<F: FnMut()>(mut f: F, expected_res: libc::c_int) {
    match unsafe { libc::fork() } {
        -1 => panic!("{}", io::Error::last_os_error()),

        0 => {
            std::panic::set_hook(Box::new(|_| unsafe {
                libc::_exit(1);
            }));

            f();

            unsafe {
                libc::_exit(0);
            }
        }

        pid => {
            let mut wstatus = 0;
            assert_eq!(
                unsafe { libc::waitpid(pid, &mut wstatus, 0) },
                pid,
                "{}",
                io::Error::last_os_error()
            );

            let res = if libc::WIFSIGNALED(wstatus) {
                -libc::WTERMSIG(wstatus)
            } else {
                libc::WEXITSTATUS(wstatus)
            };

            assert_eq!(res, expected_res);
        }
    }
}

#[test]
fn test_setpriority_eperm() {
    let mut filter = Filter::new(Action::Allow).unwrap();

    filter
        .add_rule(
            Action::Errno(libc::EPERM),
            resolve_syscall_name("setpriority").unwrap(),
            &[],
        )
        .unwrap();

    fork_and_check(
        || {
            let prio = getprio(0).unwrap();

            setprio(prio).unwrap();

            filter.load().unwrap();

            assert_eq!(setprio(prio).unwrap_err().raw_os_error(), Some(libc::EPERM));
        },
        0,
    );
}

#[test]
fn test_setpriority_eperm_exact() {
    let mut filter = Filter::new(Action::Allow).unwrap();

    filter
        .add_rule_exact(
            Action::Errno(libc::EPERM),
            resolve_syscall_name("setpriority").unwrap(),
            &[],
        )
        .unwrap();

    fork_and_check(
        || {
            let prio = getprio(0).unwrap();

            setprio(prio).unwrap();

            filter.load().unwrap();

            assert_eq!(setprio(prio).unwrap_err().raw_os_error(), Some(libc::EPERM));
        },
        0,
    );
}

#[test]
fn test_setpriority_merge() {
    let mut filter = Filter::new(Action::Allow).unwrap();
    let mut filter2 = Filter::new(Action::Allow).unwrap();

    filter2
        .add_rule_exact(
            Action::Errno(libc::EPERM),
            resolve_syscall_name("setpriority").unwrap(),
            &[],
        )
        .unwrap();

    filter.remove_arch(Arch::NATIVE).unwrap();
    filter.add_arch(arch_nonnative()).unwrap();
    filter.merge(filter2).unwrap();

    fork_and_check(
        || {
            let prio = getprio(0).unwrap();

            setprio(prio).unwrap();

            filter.load().unwrap();

            assert_eq!(setprio(prio).unwrap_err().raw_os_error(), Some(libc::EPERM));
        },
        0,
    );
}

#[test]
fn test_getpriority_pid1_kill() {
    let mut filter = Filter::new(Action::Allow).unwrap();

    filter
        .add_rule(
            Action::Errno(libc::EPERM),
            resolve_syscall_name("getpriority").unwrap(),
            &[Arg::new_eq(1, 1)],
        )
        .unwrap();

    fork_and_check(
        || {
            getprio(0).unwrap();
            getprio(1).unwrap();

            filter.load().unwrap();

            getprio(0).unwrap();
            assert_eq!(getprio(1).unwrap_err().raw_os_error(), Some(libc::EPERM));
        },
        0,
    );
}
