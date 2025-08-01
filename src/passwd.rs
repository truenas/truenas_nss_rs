use libc::{c_char, c_int, gid_t, uid_t, passwd};
use std::ffi::{CStr, CString};
use std::mem;

use crate::{NssError, NssResult, NssModule, NssOperation, NssReturnCode};
use crate::nss_common::get_nss_function;

const PASSWD_INIT_BUFLEN: usize = 1024;

#[derive(Debug, Clone)]
pub struct PasswdEntry {
    pub pw_name: String,
    pub pw_uid: uid_t,
    pub pw_gid: gid_t,
    pub pw_gecos: String,
    pub pw_dir: String,
    pub pw_shell: String,
    pub source: String,
}


unsafe fn parse_passwd_result(
    result: *const passwd,
    module: &NssModule,
) -> NssResult<Option<PasswdEntry>> {
    if result.is_null() {
        return Ok(None);
    }

    let passwd_ref = &*result;

    if passwd_ref.pw_name.is_null() {
        return Ok(None);
    }

    let pw_name = CStr::from_ptr(passwd_ref.pw_name)
        .to_str()
        .map_err(|_| NssError::InvalidUtf8)?
        .to_string();

    let pw_gecos = if passwd_ref.pw_gecos.is_null() {
        String::new()
    } else {
        CStr::from_ptr(passwd_ref.pw_gecos)
            .to_str()
            .map_err(|_| NssError::InvalidUtf8)?
            .to_string()
    };

    let pw_dir = if passwd_ref.pw_dir.is_null() {
        String::new()
    } else {
        CStr::from_ptr(passwd_ref.pw_dir)
            .to_str()
            .map_err(|_| NssError::InvalidUtf8)?
            .to_string()
    };

    let pw_shell = if passwd_ref.pw_shell.is_null() {
        String::new()
    } else {
        CStr::from_ptr(passwd_ref.pw_shell)
            .to_str()
            .map_err(|_| NssError::InvalidUtf8)?
            .to_string()
    };

    Ok(Some(PasswdEntry {
        pw_name,
        pw_uid: passwd_ref.pw_uid,
        pw_gid: passwd_ref.pw_gid,
        pw_gecos,
        pw_dir,
        pw_shell,
        source: module.upper_name().to_string(),
    }))
}

type GetPwNameFn = unsafe extern "C" fn(
    name: *const c_char,
    result: *mut passwd,
    buffer: *mut c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int;

unsafe fn getpwnam_r_impl(
    name: &str,
    module: NssModule,
    buffer_len: usize,
) -> NssResult<Option<PasswdEntry>> {
    let func_ptr = get_nss_function(NssOperation::GetPwNam, module)?;
    let getpwnam_r: GetPwNameFn = mem::transmute(func_ptr);

    let name_c = CString::new(name).map_err(|_| NssError::InvalidUtf8)?;
    let mut result: passwd = mem::zeroed();
    let mut buffer = vec![0u8; buffer_len];
    let mut errno: c_int = 0;

    let ret_code = getpwnam_r(
        name_c.as_ptr(),
        &mut result,
        buffer.as_mut_ptr().cast::<c_char>(),
        buffer_len,
        &mut errno,
    );

    match errno {
        0 => {} // Success
        libc::ERANGE => {
            // Buffer too small, try with larger buffer
            return getpwnam_r_impl(name, module, buffer_len * 2);
        }
        _ => {
            return Err(NssError::NssOperationFailed {
                errno: errno.unsigned_abs(),
                operation: NssOperation::GetPwNam,
                return_code: NssReturnCode::from(ret_code),
                module,
            });
        }
    }

    let nss_code = NssReturnCode::from(ret_code);
    if nss_code == NssReturnCode::NotFound {
        return Ok(None);
    }

    if nss_code != NssReturnCode::Success {
        return Err(NssError::NssOperationFailed {
            errno: errno.unsigned_abs(),
            operation: NssOperation::GetPwNam,
            return_code: nss_code,
            module,
        });
    }

    parse_passwd_result(&result, &module)
}

type GetPwUidFn = unsafe extern "C" fn(
    uid: uid_t,
    result: *mut passwd,
    buffer: *mut c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int;

unsafe fn getpwuid_r_impl(
    uid: uid_t,
    module: NssModule,
    buffer_len: usize,
) -> NssResult<Option<PasswdEntry>> {
    let func_ptr = get_nss_function(NssOperation::GetPwUid, module)?;
    let getpwuid_r: GetPwUidFn = mem::transmute(func_ptr);

    let mut result: passwd = mem::zeroed();
    let mut buffer = vec![0u8; buffer_len];
    let mut errno: c_int = 0;

    let ret_code = getpwuid_r(
        uid,
        &mut result,
        buffer.as_mut_ptr().cast::<c_char>(),
        buffer_len,
        &mut errno,
    );

    match errno {
        0 => {} // Success
        libc::ERANGE => {
            // Buffer too small, try with larger buffer
            return getpwuid_r_impl(uid, module, buffer_len * 2);
        }
        _ => {
            return Err(NssError::NssOperationFailed {
                errno: errno.unsigned_abs(),
                operation: NssOperation::GetPwUid,
                return_code: NssReturnCode::from(ret_code),
                module,
            });
        }
    }

    let nss_code = NssReturnCode::from(ret_code);
    if nss_code == NssReturnCode::NotFound {
        return Ok(None);
    }

    if nss_code != NssReturnCode::Success {
        return Err(NssError::NssOperationFailed {
            errno: errno.unsigned_abs(),
            operation: NssOperation::GetPwUid,
            return_code: nss_code,
            module,
        });
    }

    parse_passwd_result(&result, &module)
}

/// Get password entry by username.
///
/// # Errors
/// Returns `NssError` if the user is not found or NSS operation fails.
pub fn getpwnam(name: &str, module: Option<NssModule>) -> NssResult<PasswdEntry> {
    let modules = match module {
        Some(m) => vec![m],
        None => vec![NssModule::Files, NssModule::Sss, NssModule::Winbind],
    };

    for mod_enum in modules {
        match unsafe { getpwnam_r_impl(name, mod_enum, PASSWD_INIT_BUFLEN) } {
            Ok(Some(entry)) => return Ok(entry),
            Ok(None) => continue,
            Err(NssError::NssOperationFailed { return_code: NssReturnCode::Unavail, .. }) => continue,
            Err(NssError::LibraryError(_)) => continue, // Skip unavailable modules
            Err(e) => return Err(e),
        }
    }

    Err(NssError::NssOperationFailed {
        errno: 0,
        operation: NssOperation::GetPwNam,
        return_code: NssReturnCode::NotFound,
        module: NssModule::Files, // Placeholder
    })
}

/// Get password entry by user ID.
///
/// # Errors
/// Returns `NssError` if the user is not found or NSS operation fails.
pub fn getpwuid(uid: uid_t, module: Option<NssModule>) -> NssResult<PasswdEntry> {
    let modules = match module {
        Some(m) => vec![m],
        None => vec![NssModule::Files, NssModule::Sss, NssModule::Winbind],
    };

    for mod_enum in modules {
        match unsafe { getpwuid_r_impl(uid, mod_enum, PASSWD_INIT_BUFLEN) } {
            Ok(Some(entry)) => return Ok(entry),
            Ok(None) => continue,
            Err(NssError::NssOperationFailed { return_code: NssReturnCode::Unavail, .. }) => continue,
            Err(NssError::LibraryError(_)) => continue, // Skip unavailable modules
            Err(e) => return Err(e),
        }
    }

    Err(NssError::NssOperationFailed {
        errno: 0,
        operation: NssOperation::GetPwUid,
        return_code: NssReturnCode::NotFound,
        module: NssModule::Files, // Placeholder
    })
}

type SetPwEntFn = unsafe extern "C" fn() -> c_int;
type EndPwEntFn = unsafe extern "C" fn() -> c_int;
type GetPwEntFn = unsafe extern "C" fn(
    result: *mut passwd,
    buffer: *mut c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int;

unsafe fn setpwent_impl(module: NssModule) -> NssResult<()> {
    let func_ptr = get_nss_function(NssOperation::SetPwEnt, module)?;
    let setpwent: SetPwEntFn = mem::transmute(func_ptr);

    let ret_code = setpwent();
    let nss_code = NssReturnCode::from(ret_code);

    if nss_code != NssReturnCode::Success {
        return Err(NssError::NssOperationFailed {
            errno: 0,
            operation: NssOperation::SetPwEnt,
            return_code: nss_code,
            module,
        });
    }

    Ok(())
}

unsafe fn endpwent_impl(module: NssModule) -> NssResult<()> {
    let func_ptr = get_nss_function(NssOperation::EndPwEnt, module)?;
    let endpwent: EndPwEntFn = mem::transmute(func_ptr);

    let ret_code = endpwent();
    let nss_code = NssReturnCode::from(ret_code);

    if nss_code != NssReturnCode::Success {
        return Err(NssError::NssOperationFailed {
            errno: 0,
            operation: NssOperation::EndPwEnt,
            return_code: nss_code,
            module,
        });
    }

    Ok(())
}

unsafe fn getpwent_r_impl(
    module: NssModule,
    buffer_len: usize,
) -> NssResult<Option<PasswdEntry>> {
    let func_ptr = get_nss_function(NssOperation::GetPwEnt, module)?;
    let getpwent_r: GetPwEntFn = mem::transmute(func_ptr);

    let mut result: passwd = mem::zeroed();
    let mut buffer = vec![0u8; buffer_len];
    let mut errno: c_int = 0;

    let ret_code = getpwent_r(
        &mut result,
        buffer.as_mut_ptr().cast::<c_char>(),
        buffer_len,
        &mut errno,
    );

    match errno {
        0 => {} // Success
        libc::ERANGE => {
            // Buffer too small, try with larger buffer
            return getpwent_r_impl(module, buffer_len * 2);
        }
        _ => {
            return Err(NssError::NssOperationFailed {
                errno: errno.unsigned_abs(),
                operation: NssOperation::GetPwEnt,
                return_code: NssReturnCode::from(ret_code),
                module,
            });
        }
    }

    let nss_code = NssReturnCode::from(ret_code);
    if nss_code != NssReturnCode::Success {
        return Ok(None);
    }

    parse_passwd_result(&result, &module)
}

pub struct PasswdIterator {
    module: NssModule,
    initialized: bool,
}

impl PasswdIterator {
    #[must_use]
    pub fn new(module: NssModule) -> Self {
        PasswdIterator {
            module,
            initialized: false,
        }
    }
}

impl Iterator for PasswdIterator {
    type Item = NssResult<PasswdEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if !self.initialized {
                if let Err(e) = setpwent_impl(self.module) {
                    return Some(Err(e));
                }
                self.initialized = true;
            }

            match getpwent_r_impl(self.module, PASSWD_INIT_BUFLEN) {
                Ok(Some(entry)) => Some(Ok(entry)),
                Ok(None) => None,
                Err(e) => Some(Err(e)),
            }
        }
    }
}

impl Drop for PasswdIterator {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                let _ = endpwent_impl(self.module);
            }
        }
    }
}

/// Create an iterator for password entries from the specified NSS module.
#[must_use]
pub fn iterpw(module: NssModule) -> PasswdIterator {
    PasswdIterator::new(module)
}

/// Get all password entries from the specified NSS module(s).
///
/// # Errors
/// Returns `NssError` if NSS operation fails.
pub fn getpwall(module: Option<NssModule>) -> NssResult<Vec<PasswdEntry>> {
    let modules = match module {
        Some(m) => vec![m],
        None => vec![NssModule::Files, NssModule::Sss, NssModule::Winbind],
    };

    let mut all_entries = Vec::new();

    for mod_enum in modules {
        let mut entries = Vec::new();
        for result in iterpw(mod_enum) {
            match result {
                Ok(entry) => entries.push(entry),
                Err(NssError::NssOperationFailed { return_code: NssReturnCode::Unavail, .. }) => break,
                Err(NssError::LibraryError(_)) => {
                    // Library not available (e.g., winbind/sss not installed), skip this module
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        all_entries.extend(entries);
    }

    Ok(all_entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passwd_entry_creation() {
        let entry = PasswdEntry {
            pw_name: "testuser".to_string(),
            pw_uid: 1000,
            pw_gid: 1000,
            pw_gecos: "Test User".to_string(),
            pw_dir: "/home/testuser".to_string(),
            pw_shell: "/bin/bash".to_string(),
            source: "files".to_string(),
        };

        assert_eq!(entry.pw_name, "testuser");
        assert_eq!(entry.pw_uid, 1000);
        assert_eq!(entry.pw_gid, 1000);
        assert_eq!(entry.pw_gecos, "Test User");
        assert_eq!(entry.pw_dir, "/home/testuser");
        assert_eq!(entry.pw_shell, "/bin/bash");
        assert_eq!(entry.source, "files");
    }


    #[test]
    fn test_passwd_iterator_creation() {
        let iterator = PasswdIterator::new(NssModule::Files);
        assert_eq!(iterator.module, NssModule::Files);
        assert!(!iterator.initialized);
    }

    #[test]
    fn test_passwd_iterator_function() {
        let iterator = iterpw(NssModule::Files);
        assert_eq!(iterator.module, NssModule::Files);
        assert!(!iterator.initialized);
    }

    // Note: Most NSS function tests would require actual NSS libraries to be present
    // and would be better suited for integration tests rather than unit tests
}