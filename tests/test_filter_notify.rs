#![cfg(feature = "libseccomp-2-5")]

use std::io;

use libscmp::{resolve_syscall_name, Action, Arch, Filter, NotificationResponse};

fn setprio(value: libc::c_int) -> io::Result<()> {
    if unsafe { libc::setpriority(0, 0, value) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn fork_and_run<F: FnMut()>(mut f: F) -> libc::pid_t {
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

        pid => return pid,
    }
}

fn check_status(pid: libc::pid_t, expected_res: libc::c_int) {
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

fn test_notify_1() {
    // Uses resp.set_val() to return the error

    let mut filter = Filter::new(Action::Allow).unwrap();

    filter
        .add_rule(
            Action::Notify,
            resolve_syscall_name("setpriority").unwrap(),
            &[],
        )
        .unwrap();

    filter.load().unwrap();

    let pid = fork_and_run(|| {
        assert_eq!(setprio(0).unwrap_err().raw_os_error(), Some(libc::ENOTSUP));
    });

    let notif = filter.receive_notify().unwrap();

    assert_eq!(notif.pid(), pid as u32);
    assert_eq!(notif.arch(), Arch::native());
    assert_eq!(
        notif.syscall(),
        resolve_syscall_name("setpriority").unwrap()
    );
    assert_eq!(&notif.args()[..3], &[0, 0, 0]);

    assert!(notif.is_id_valid(filter.get_notify_fd().unwrap()));

    let mut resp = NotificationResponse::new();
    resp.set_id(notif.id());
    resp.set_val(-libc::ENOTSUP as i64);
    filter.respond_notify(&mut resp).unwrap();

    check_status(pid, 0);
}

fn test_notify_2() {
    // Uses resp.set_error() to return the error

    let mut filter = Filter::new(Action::Allow).unwrap();

    filter
        .add_rule(
            Action::Notify,
            resolve_syscall_name("setpriority").unwrap(),
            &[],
        )
        .unwrap();

    filter.load().unwrap();

    let pid = fork_and_run(|| {
        assert_eq!(setprio(0).unwrap_err().raw_os_error(), Some(libc::ENOTSUP));
    });

    let notif = filter.receive_notify().unwrap();

    assert_eq!(notif.pid(), pid as u32);
    assert_eq!(notif.arch(), Arch::native());
    assert_eq!(
        notif.syscall(),
        resolve_syscall_name("setpriority").unwrap()
    );
    assert_eq!(&notif.args()[..3], &[0, 0, 0]);

    assert!(notif.is_id_valid(filter.get_notify_fd().unwrap()));

    let mut resp = NotificationResponse::new();
    resp.set_id(notif.id());
    resp.set_error(-libc::ENOTSUP);
    filter.respond_notify(&mut resp).unwrap();

    check_status(pid, 0);
}

#[test]
fn test_notify() {
    // Run in different processes because the notification fd is global state and things won't be
    // handled properly otherwise.
    check_status(fork_and_run(test_notify_1), 0);
    check_status(fork_and_run(test_notify_2), 0);
}
