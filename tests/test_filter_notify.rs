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

#[test]
fn test_notify() {
    let mut filter = Filter::new(Action::Allow).unwrap();

    filter
        .add_rule(
            Action::Notify,
            resolve_syscall_name("setpriority").unwrap(),
            &[],
        )
        .unwrap();

    filter.load().unwrap();

    match unsafe { libc::fork() } {
        -1 => panic!("{}", io::Error::last_os_error()),

        0 => {
            std::panic::set_hook(Box::new(|_| unsafe {
                libc::_exit(1);
            }));

            assert_eq!(setprio(0).unwrap_err().raw_os_error(), Some(libc::ENOTSUP));

            unsafe {
                libc::_exit(0);
            }
        }

        pid => {
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

            let mut wstatus = 0;
            assert_eq!(
                unsafe { libc::waitpid(pid, &mut wstatus, 0) },
                pid,
                "{}",
                io::Error::last_os_error()
            );

            assert!(libc::WIFEXITED(wstatus));
            assert_eq!(libc::WEXITSTATUS(wstatus), 0);
        }
    }
}
