use std::io;
use std::os::unix::prelude::*;
use std::ptr::NonNull;

use crate::sys;

unsafe fn notify_alloc(
    req_ptr: *mut *mut sys::seccomp_notif,
    resp_ptr: *mut *mut sys::seccomp_notif_resp,
) {
    if sys::seccomp_notify_alloc(req_ptr, resp_ptr) != 0 {
        std::alloc::handle_alloc_error(std::alloc::Layout::from_size_align_unchecked(
            std::mem::size_of::<sys::seccomp_notif>(),
            std::mem::size_of::<sys::seccomp_notif>().next_power_of_two(),
        ))
    }
}

/// Represents a seccomp notification.
///
/// This struct has getter methods for the various fields of the notification.
pub struct Notification {
    req: NonNull<sys::seccomp_notif>,
}

impl Notification {
    /// Receive a seccomp notification from the given notification fd.
    pub fn receive(fd: RawFd) -> io::Result<Self> {
        let mut res = Self::new();
        res.receive_into(fd)?;
        Ok(res)
    }

    #[inline]
    fn new() -> Self {
        let mut req_ptr = std::ptr::null_mut();
        unsafe {
            notify_alloc(&mut req_ptr, std::ptr::null_mut());
        }

        Self {
            req: NonNull::new(req_ptr).unwrap(),
        }
    }

    #[inline]
    pub fn id(&self) -> u64 {
        unsafe { self.req.as_ref().id }
    }

    #[inline]
    pub fn pid(&self) -> u32 {
        unsafe { self.req.as_ref().pid }
    }

    #[inline]
    pub fn flags(&self) -> u32 {
        unsafe { self.req.as_ref().flags }
    }

    #[inline]
    pub fn syscall(&self) -> libc::c_int {
        unsafe { self.req.as_ref().data.nr }
    }

    pub fn arch(&self) -> crate::Arch {
        crate::Arch::get_arch(unsafe { self.req.as_ref().data.arch })
            .expect("Unrecognized architecture returned from libseccomp")
    }

    #[inline]
    pub fn instruction_pointer(&self) -> u64 {
        unsafe { self.req.as_ref().data.instruction_pointer }
    }

    #[inline]
    pub fn args(&self) -> &[u64; 6] {
        unsafe { &self.req.as_ref().data.args }
    }

    fn receive_into(&mut self, fd: RawFd) -> io::Result<()> {
        crate::check_status(unsafe { sys::seccomp_notify_receive(fd, self.req.as_ptr()) })
    }

    /// Check if the notification ID as returned by [`id()`] is still valid.
    ///
    /// See seccomp_notify_id_valid(3) for an explanation of why this is necessary.
    ///
    /// [`id()`](#method.id)
    #[inline]
    pub fn is_id_valid(&self, fd: RawFd) -> bool {
        notify_id_valid(fd, self.id())
    }
}

impl Drop for Notification {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            sys::seccomp_notify_free(self.req.as_ptr(), std::ptr::null_mut());
        }
    }
}

/// Represents a response to a seccomp notification.
///
/// This struct has setter methods for the various fields of the response.
pub struct NotificationResponse {
    resp: NonNull<sys::seccomp_notif_resp>,
}

impl NotificationResponse {
    /// Create a new `NotificationResponse` with all fields zeroed.
    #[inline]
    pub fn new() -> Self {
        let mut resp_ptr = std::ptr::null_mut();
        unsafe {
            notify_alloc(std::ptr::null_mut(), &mut resp_ptr);
        }

        Self {
            resp: NonNull::new(resp_ptr).unwrap(),
        }
    }

    #[inline]
    pub fn set_id(&mut self, id: u64) {
        unsafe { self.resp.as_mut() }.id = id;
    }

    #[inline]
    pub fn set_val(&mut self, val: i64) {
        unsafe { self.resp.as_mut() }.val = val;
    }

    #[inline]
    pub fn set_error(&mut self, error: i32) {
        unsafe { self.resp.as_mut() }.error = error;
    }

    #[inline]
    pub fn set_flags(&mut self, flags: u32) {
        unsafe { self.resp.as_mut() }.flags = flags;
    }

    /// Send a response along the given notification file descriptor.
    pub fn send_response(&mut self, fd: RawFd) -> io::Result<()> {
        crate::check_status(unsafe { sys::seccomp_notify_respond(fd, self.resp.as_ptr()) })
    }
}

impl Drop for NotificationResponse {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            sys::seccomp_notify_free(std::ptr::null_mut(), self.resp.as_ptr());
        }
    }
}

/// Check if the given notification ID is still valid.
///
/// See seccomp_notify_id_valid(3) for an explanation of why this is necessary.
#[inline]
pub fn notify_id_valid(fd: RawFd, id: u64) -> bool {
    unsafe { sys::seccomp_notify_id_valid(fd, id) == 0 }
}
