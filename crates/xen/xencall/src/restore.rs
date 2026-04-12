//! Runtime-loaded FFI bindings for xc_domain_restore from libxenguest.
//!
//! Uses dlopen to load libxenctrl and libxenguest at runtime, avoiding
//! link-time dependencies on Xen libraries. This keeps krata-xencall
//! compilable on non-Xen hosts (build nodes, CI, macOS).

use crate::error::{Error, Result};
use std::ffi::c_void;

/// Result of a successful domain restore.
#[derive(Debug, Clone)]
pub struct RestoreResult {
    /// Xenstore shared page MFN (machine frame number).
    pub store_mfn: u64,
    /// Console shared page MFN.
    pub console_mfn: u64,
}

/// Matches Xen's `struct restore_callbacks` from xenguest.h.
///
/// xc_domain_restore dereferences the callbacks pointer without null-checking,
/// so we must provide a valid struct even if all function pointers are None.
#[repr(C)]
struct RestoreCallbacks {
    static_data_done: Option<unsafe extern "C" fn(u32, *mut c_void) -> i32>,
    suspend: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    postcopy: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    checkpoint: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    wait_checkpoint: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    restore_results: Option<unsafe extern "C" fn(u64, u64, *mut c_void)>,
    data: *mut c_void,
}

/// Data passed through callbacks->data to capture restore_results output.
struct CallbackData {
    store_mfn: u64,
    console_mfn: u64,
}

/// C-callable callback for restore_results. Writes GFNs to CallbackData.
unsafe extern "C" fn on_restore_results(store_gfn: u64, console_gfn: u64, data: *mut c_void) {
    let cb_data = &mut *(data as *mut CallbackData);
    cb_data.store_mfn = store_gfn;
    cb_data.console_mfn = console_gfn;
}

/// Restore a domain from a checkpoint stream.
///
/// The domain must already be created (via `create_domain` hypercall) with
/// appropriate max_mem, max_vcpus, and address_size set. The checkpoint fd
/// must point to a raw xc save stream (NOT an xl-wrapped file).
///
/// Event channels for xenstore and console must be pre-allocated via
/// `evtchn_alloc_unbound`.
///
/// Returns the store and console MFNs that xc_domain_restore writes to
/// the guest's shared_info/start_info pages.
pub fn restore_domain(
    domid: u32,
    checkpoint_fd: i32,
    store_evtchn: u32,
    console_evtchn: u32,
) -> Result<RestoreResult> {
    // Load Xen libraries at runtime via dlopen
    let xenctrl = unsafe { libc::dlopen(b"libxenctrl.so\0".as_ptr() as _, libc::RTLD_NOW) };
    if xenctrl.is_null() {
        let err = unsafe { std::ffi::CStr::from_ptr(libc::dlerror()) };
        return Err(Error::RestoreFailed(format!(
            "dlopen libxenctrl.so: {}",
            err.to_string_lossy()
        )));
    }
    let xenguest = unsafe { libc::dlopen(b"libxenguest.so\0".as_ptr() as _, libc::RTLD_NOW) };
    if xenguest.is_null() {
        let err = unsafe { std::ffi::CStr::from_ptr(libc::dlerror()) };
        return Err(Error::RestoreFailed(format!(
            "dlopen libxenguest.so: {}",
            err.to_string_lossy()
        )));
    }

    // Resolve function pointers
    type XcInterfaceOpenFn = unsafe extern "C" fn(*mut c_void, *mut c_void, u32) -> *mut c_void;
    type XcInterfaceCloseFn = unsafe extern "C" fn(*mut c_void) -> i32;
    // 13 parameters: xch, io_fd, dom, store_evtchn, store_mfn, store_domid,
    //   console_evtchn, console_mfn, console_domid, stream_type,
    //   callbacks, send_back_fd, memflags
    type XcDomainRestoreFn = unsafe extern "C" fn(
        *mut c_void,
        i32,
        u32,
        u32,
        *mut u64,
        u32,
        u32,
        *mut u64,
        u32,
        i32,
        *const RestoreCallbacks,
        i32,
        u32,
    ) -> i32;

    let xc_open: XcInterfaceOpenFn = unsafe {
        let sym = libc::dlsym(xenctrl, b"xc_interface_open\0".as_ptr() as _);
        if sym.is_null() {
            return Err(Error::RestoreFailed("xc_interface_open not found".into()));
        }
        std::mem::transmute(sym)
    };
    let xc_close: XcInterfaceCloseFn = unsafe {
        let sym = libc::dlsym(xenctrl, b"xc_interface_close\0".as_ptr() as _);
        if sym.is_null() {
            return Err(Error::RestoreFailed("xc_interface_close not found".into()));
        }
        std::mem::transmute(sym)
    };
    let xc_restore: XcDomainRestoreFn = unsafe {
        let sym = libc::dlsym(xenguest, b"xc_domain_restore\0".as_ptr() as _);
        if sym.is_null() {
            return Err(Error::RestoreFailed("xc_domain_restore not found".into()));
        }
        std::mem::transmute(sym)
    };

    // Open xc_interface
    let xch = unsafe { xc_open(std::ptr::null_mut(), std::ptr::null_mut(), 0) };
    if xch.is_null() {
        return Err(Error::RestoreFailed("xc_interface_open returned null".into()));
    }

    let mut store_mfn: u64 = 0;
    let mut console_mfn: u64 = 0;

    // Provide callbacks struct -- xc_domain_restore dereferences it without
    // null-checking. restore_results callback captures the output GFNs.
    let mut cb_data = CallbackData {
        store_mfn: 0,
        console_mfn: 0,
    };
    let callbacks = RestoreCallbacks {
        static_data_done: None,
        suspend: None,
        postcopy: None,
        checkpoint: None,
        wait_checkpoint: None,
        restore_results: Some(on_restore_results),
        data: &mut cb_data as *mut CallbackData as *mut c_void,
    };

    let ret = unsafe {
        xc_restore(
            xch,
            checkpoint_fd,
            domid,
            store_evtchn,
            &mut store_mfn,
            0, // store_domid (dom0)
            console_evtchn,
            &mut console_mfn,
            0, // console_domid (dom0)
            0, // XC_STREAM_PLAIN
            &callbacks,
            -1, // no send-back fd
            0,  // memflags
        )
    };

    unsafe { xc_close(xch) };

    if ret != 0 {
        return Err(Error::RestoreFailed(format!(
            "xc_domain_restore failed: return code {ret}"
        )));
    }

    // Use callback results if the output pointers weren't written
    if store_mfn == 0 && cb_data.store_mfn != 0 {
        store_mfn = cb_data.store_mfn;
    }
    if console_mfn == 0 && cb_data.console_mfn != 0 {
        console_mfn = cb_data.console_mfn;
    }

    Ok(RestoreResult {
        store_mfn,
        console_mfn,
    })
}
