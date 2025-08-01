use libc::{c_char, c_int, gid_t, group};
use std::ffi::{CStr, CString};
use std::mem;

use crate::{NssError, NssResult, NssModule, NssOperation, NssReturnCode};
use crate::nss_common::get_nss_function;

const GROUP_INIT_BUFLEN: usize = 1024;

#[derive(Debug, Clone)]
pub struct GroupEntry {
    pub gr_name: String,
    pub gr_gid: gid_t,
    pub gr_mem: Vec<String>,
    pub source: String,
}


unsafe fn parse_group_result(
    result: *const group,
    module: &NssModule,
) -> NssResult<Option<GroupEntry>> {
    if result.is_null() {
        return Ok(None);
    }

    let group_ref = &*result;

    if group_ref.gr_name.is_null() {
        return Ok(None);
    }

    let gr_name = CStr::from_ptr(group_ref.gr_name)
        .to_str()
        .map_err(|_| NssError::InvalidUtf8)?
        .to_string();

    let mut gr_mem = Vec::new();
    if !group_ref.gr_mem.is_null() {
        let mut i = 0;
        loop {
            let member_ptr = *group_ref.gr_mem.offset(i);
            if member_ptr.is_null() {
                break;
            }
            let member = CStr::from_ptr(member_ptr)
                .to_str()
                .map_err(|_| NssError::InvalidUtf8)?
                .to_string();
            gr_mem.push(member);
            i += 1;
        }
    }

    Ok(Some(GroupEntry {
        gr_name,
        gr_gid: group_ref.gr_gid,
        gr_mem,
        source: module.upper_name().to_string(),
    }))
}

type GetGrNameFn = unsafe extern "C" fn(
    name: *const c_char,
    result: *mut group,
    buffer: *mut c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int;

unsafe fn getgrnam_r_impl(
    name: &str,
    module: NssModule,
    buffer_len: usize,
) -> NssResult<Option<GroupEntry>> {
    let func_ptr = get_nss_function(NssOperation::GetGrNam, module)?;
    let getgrnam_r: GetGrNameFn = mem::transmute(func_ptr);

    let name_c = CString::new(name).map_err(|_| NssError::InvalidUtf8)?;
    let mut result: group = mem::zeroed();
    let mut buffer = vec![0u8; buffer_len];
    let mut errno: c_int = 0;

    let ret_code = getgrnam_r(
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
            return getgrnam_r_impl(name, module, buffer_len * 2);
        }
        _ => {
            return Err(NssError::NssOperationFailed {
                errno: errno.unsigned_abs(),
                operation: NssOperation::GetGrNam,
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
            operation: NssOperation::GetGrNam,
            return_code: nss_code,
            module,
        });
    }

    parse_group_result(&result, &module)
}

type GetGrGidFn = unsafe extern "C" fn(
    gid: gid_t,
    result: *mut group,
    buffer: *mut c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int;

unsafe fn getgrgid_r_impl(
    gid: gid_t,
    module: NssModule,
    buffer_len: usize,
) -> NssResult<Option<GroupEntry>> {
    let func_ptr = get_nss_function(NssOperation::GetGrGid, module)?;
    let getgrgid_r: GetGrGidFn = mem::transmute(func_ptr);

    let mut result: group = mem::zeroed();
    let mut buffer = vec![0u8; buffer_len];
    let mut errno: c_int = 0;

    let ret_code = getgrgid_r(
        gid,
        &mut result,
        buffer.as_mut_ptr().cast::<c_char>(),
        buffer_len,
        &mut errno,
    );

    match errno {
        0 => {} // Success
        libc::ERANGE => {
            // Buffer too small, try with larger buffer
            return getgrgid_r_impl(gid, module, buffer_len * 2);
        }
        _ => {
            return Err(NssError::NssOperationFailed {
                errno: errno.unsigned_abs(),
                operation: NssOperation::GetGrGid,
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
            operation: NssOperation::GetGrGid,
            return_code: nss_code,
            module,
        });
    }

    parse_group_result(&result, &module)
}

/// Get group entry by group name.
///
/// # Errors
/// Returns `NssError` if the group is not found or NSS operation fails.
pub fn getgrnam(name: &str, module: Option<NssModule>) -> NssResult<GroupEntry> {
    let modules = match module {
        Some(m) => vec![m],
        None => vec![NssModule::Files, NssModule::Sss, NssModule::Winbind],
    };

    for mod_enum in modules {
        match unsafe { getgrnam_r_impl(name, mod_enum, GROUP_INIT_BUFLEN) } {
            Ok(Some(entry)) => return Ok(entry),
            Ok(None) => continue,
            Err(NssError::NssOperationFailed { return_code: NssReturnCode::Unavail, .. }) => continue,
            Err(NssError::LibraryError(_)) => continue, // Skip unavailable modules
            Err(e) => return Err(e),
        }
    }

    Err(NssError::NssOperationFailed {
        errno: 0,
        operation: NssOperation::GetGrNam,
        return_code: NssReturnCode::NotFound,
        module: NssModule::Files, // Placeholder
    })
}

/// Get group entry by group ID.
///
/// # Errors
/// Returns `NssError` if the group is not found or NSS operation fails.
pub fn getgrgid(gid: gid_t, module: Option<NssModule>) -> NssResult<GroupEntry> {
    let modules = match module {
        Some(m) => vec![m],
        None => vec![NssModule::Files, NssModule::Sss, NssModule::Winbind],
    };

    for mod_enum in modules {
        match unsafe { getgrgid_r_impl(gid, mod_enum, GROUP_INIT_BUFLEN) } {
            Ok(Some(entry)) => return Ok(entry),
            Ok(None) => continue,
            Err(NssError::NssOperationFailed { return_code: NssReturnCode::Unavail, .. }) => continue,
            Err(NssError::LibraryError(_)) => continue, // Skip unavailable modules
            Err(e) => return Err(e),
        }
    }

    Err(NssError::NssOperationFailed {
        errno: 0,
        operation: NssOperation::GetGrGid,
        return_code: NssReturnCode::NotFound,
        module: NssModule::Files, // Placeholder
    })
}

type SetGrEntFn = unsafe extern "C" fn() -> c_int;
type EndGrEntFn = unsafe extern "C" fn() -> c_int;
type GetGrEntFn = unsafe extern "C" fn(
    result: *mut group,
    buffer: *mut c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int;

unsafe fn setgrent_impl(module: NssModule) -> NssResult<()> {
    let func_ptr = get_nss_function(NssOperation::SetGrEnt, module)?;
    let setgrent: SetGrEntFn = mem::transmute(func_ptr);

    let ret_code = setgrent();
    let nss_code = NssReturnCode::from(ret_code);

    if nss_code != NssReturnCode::Success {
        return Err(NssError::NssOperationFailed {
            errno: 0,
            operation: NssOperation::SetGrEnt,
            return_code: nss_code,
            module,
        });
    }

    Ok(())
}

unsafe fn endgrent_impl(module: NssModule) -> NssResult<()> {
    let func_ptr = get_nss_function(NssOperation::EndGrEnt, module)?;
    let endgrent: EndGrEntFn = mem::transmute(func_ptr);

    let ret_code = endgrent();
    let nss_code = NssReturnCode::from(ret_code);

    if nss_code != NssReturnCode::Success {
        return Err(NssError::NssOperationFailed {
            errno: 0,
            operation: NssOperation::EndGrEnt,
            return_code: nss_code,
            module,
        });
    }

    Ok(())
}

unsafe fn getgrent_r_impl(
    module: NssModule,
    buffer_len: usize,
) -> NssResult<Option<GroupEntry>> {
    let func_ptr = get_nss_function(NssOperation::GetGrEnt, module)?;
    let getgrent_r: GetGrEntFn = mem::transmute(func_ptr);

    let mut result: group = mem::zeroed();
    let mut buffer = vec![0u8; buffer_len];
    let mut errno: c_int = 0;

    let ret_code = getgrent_r(
        &mut result,
        buffer.as_mut_ptr().cast::<c_char>(),
        buffer_len,
        &mut errno,
    );

    match errno {
        0 => {} // Success
        libc::ERANGE => {
            // Buffer too small, try with larger buffer
            return getgrent_r_impl(module, buffer_len * 2);
        }
        _ => {
            return Err(NssError::NssOperationFailed {
                errno: errno.unsigned_abs(),
                operation: NssOperation::GetGrEnt,
                return_code: NssReturnCode::from(ret_code),
                module,
            });
        }
    }

    let nss_code = NssReturnCode::from(ret_code);
    if nss_code != NssReturnCode::Success {
        return Ok(None);
    }

    parse_group_result(&result, &module)
}

pub struct GroupIterator {
    module: NssModule,
    initialized: bool,
}

impl GroupIterator {
    #[must_use]
    pub fn new(module: NssModule) -> Self {
        GroupIterator {
            module,
            initialized: false,
        }
    }
}

impl Iterator for GroupIterator {
    type Item = NssResult<GroupEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if !self.initialized {
                if let Err(e) = setgrent_impl(self.module) {
                    return Some(Err(e));
                }
                self.initialized = true;
            }

            match getgrent_r_impl(self.module, GROUP_INIT_BUFLEN) {
                Ok(Some(entry)) => Some(Ok(entry)),
                Ok(None) => None,
                Err(e) => Some(Err(e)),
            }
        }
    }
}

impl Drop for GroupIterator {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                let _ = endgrent_impl(self.module);
            }
        }
    }
}

/// Create an iterator for group entries from the specified NSS module.
#[must_use]
pub fn itergrp(module: NssModule) -> GroupIterator {
    GroupIterator::new(module)
}

/// Get all group entries from the specified NSS module(s).
///
/// # Errors
/// Returns `NssError` if NSS operation fails.
pub fn getgrall(module: Option<NssModule>) -> NssResult<Vec<GroupEntry>> {
    let modules = match module {
        Some(m) => vec![m],
        None => vec![NssModule::Files, NssModule::Sss, NssModule::Winbind],
    };

    let mut all_entries = Vec::new();

    for mod_enum in modules {
        let mut entries = Vec::new();
        for result in itergrp(mod_enum) {
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
    fn test_group_entry_creation() {
        let entry = GroupEntry {
            gr_name: "testgroup".to_string(),
            gr_gid: 1000,
            gr_mem: vec!["user1".to_string(), "user2".to_string()],
            source: "files".to_string(),
        };

        assert_eq!(entry.gr_name, "testgroup");
        assert_eq!(entry.gr_gid, 1000);
        assert_eq!(entry.gr_mem, vec!["user1", "user2"]);
        assert_eq!(entry.source, "files");
    }


    #[test]
    fn test_group_entry_empty_members() {
        let entry = GroupEntry {
            gr_name: "emptygroup".to_string(),
            gr_gid: 2000,
            gr_mem: vec![],
            source: "files".to_string(),
        };

        assert_eq!(entry.gr_name, "emptygroup");
        assert_eq!(entry.gr_gid, 2000);
        assert!(entry.gr_mem.is_empty());
        assert_eq!(entry.source, "files");

    }

    #[test]
    fn test_group_iterator_creation() {
        let iterator = GroupIterator::new(NssModule::Files);
        assert_eq!(iterator.module, NssModule::Files);
        assert!(!iterator.initialized);
    }

    #[test]
    fn test_group_iterator_function() {
        let iterator = itergrp(NssModule::Files);
        assert_eq!(iterator.module, NssModule::Files);
        assert!(!iterator.initialized);
    }

    // Note: Most NSS function tests would require actual NSS libraries to be present
    // and would be better suited for integration tests rather than unit tests
}