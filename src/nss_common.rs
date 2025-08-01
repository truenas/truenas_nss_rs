use libc::{c_int, dlopen, dlsym, RTLD_LAZY};
use std::ffi::CString;
use std::sync::{OnceLock, Mutex};
use std::collections::HashMap;

pub const NSS_MODULES_DIR: &str = "/usr/lib/x86_64-linux-gnu";
pub const FILES_NSS_PATH: &str = "/usr/lib/x86_64-linux-gnu/libnss_files.so.2";
pub const SSS_NSS_PATH: &str = "/usr/lib/x86_64-linux-gnu/libnss_sss.so.2";
pub const WINBIND_NSS_PATH: &str = "/usr/lib/x86_64-linux-gnu/libnss_winbind.so.2";

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NssReturnCode {
    TryAgain = -2,
    Unavail = -1,
    NotFound = 0,
    Success = 1,
    Return = 2,
}

impl From<c_int> for NssReturnCode {
    fn from(code: c_int) -> Self {
        match code {
            -2 => NssReturnCode::TryAgain,
            -1 => NssReturnCode::Unavail,
            0 => NssReturnCode::NotFound,
            1 => NssReturnCode::Success,
            2 => NssReturnCode::Return,
            _ => NssReturnCode::Unavail,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NssModule {
    Files,
    Sss,
    Winbind,
}

impl NssModule {
    #[must_use]
    pub fn path(&self) -> &'static str {
        match self {
            NssModule::Files => FILES_NSS_PATH,
            NssModule::Sss => SSS_NSS_PATH,
            NssModule::Winbind => WINBIND_NSS_PATH,
        }
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            NssModule::Files => "files",
            NssModule::Sss => "sss",
            NssModule::Winbind => "winbind",
        }
    }

    #[must_use]
    pub fn upper_name(&self) -> &'static str {
        match self {
            NssModule::Files => "FILES",
            NssModule::Sss => "SSS",
            NssModule::Winbind => "WINBIND",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NssOperation {
    GetGrNam,
    GetGrGid,
    SetGrEnt,
    EndGrEnt,
    GetGrEnt,
    GetPwNam,
    GetPwUid,
    GetPwEnt,
    SetPwEnt,
    EndPwEnt,
}

impl NssOperation {
    #[must_use]
    pub fn function_name(&self) -> &'static str {
        match self {
            NssOperation::GetGrNam => "getgrnam_r",
            NssOperation::GetGrGid => "getgrgid_r",
            NssOperation::SetGrEnt => "setgrent",
            NssOperation::EndGrEnt => "endgrent",
            NssOperation::GetGrEnt => "getgrent_r",
            NssOperation::GetPwNam => "getpwnam_r",
            NssOperation::GetPwUid => "getpwuid_r",
            NssOperation::GetPwEnt => "getpwent_r",
            NssOperation::SetPwEnt => "setpwent",
            NssOperation::EndPwEnt => "endpwent",
        }
    }

    const fn as_index(self) -> usize {
        match self {
            NssOperation::GetGrNam => 0,
            NssOperation::GetGrGid => 1,
            NssOperation::SetGrEnt => 2,
            NssOperation::EndGrEnt => 3,
            NssOperation::GetGrEnt => 4,
            NssOperation::GetPwNam => 5,
            NssOperation::GetPwUid => 6,
            NssOperation::GetPwEnt => 7,
            NssOperation::SetPwEnt => 8,
            NssOperation::EndPwEnt => 9,
        }
    }
}

const ALL_OPERATIONS: [NssOperation; 10] = [
    NssOperation::GetGrNam,
    NssOperation::GetGrGid,
    NssOperation::SetGrEnt,
    NssOperation::EndGrEnt,
    NssOperation::GetGrEnt,
    NssOperation::GetPwNam,
    NssOperation::GetPwUid,
    NssOperation::GetPwEnt,
    NssOperation::SetPwEnt,
    NssOperation::EndPwEnt,
];

/// Cached NSS library with all function pointers loaded upfront
///
/// Safety: Raw function pointers are safe to share between threads as long as
/// the underlying library remains loaded (which it does for the process lifetime).
unsafe impl Send for NssLibrary {}
unsafe impl Sync for NssLibrary {}

struct NssLibrary {
    functions: [*mut libc::c_void; 10],
}

/// Global cache of loaded NSS libraries (max 3 entries)
static NSS_LIBRARIES: OnceLock<Mutex<HashMap<NssModule, NssLibrary>>> = OnceLock::new();

/// Gets a function pointer from an NSS module library.
///
/// Libraries are loaded once per process and all function pointers are cached.
/// This eliminates the need to call dlopen/dlsym on every NSS operation.
///
/// # Safety
/// This function uses `dlopen` and `dlsym` to load shared libraries and function pointers.
/// The caller must ensure that:
/// - The returned function pointer is used correctly according to the NSS API
/// - The function is called with proper arguments and memory management
///
/// # Errors
/// Returns `NssError::LibraryError` if the library cannot be loaded or the function is not found.
/// Returns `NssError::InvalidUtf8` if string conversion fails.
///
/// # Panics
/// Panics if the internal library cache mutex is poisoned, which indicates that
/// another thread panicked while loading NSS libraries. This represents an
/// unrecoverable system-level failure and the application should terminate.
pub unsafe fn get_nss_function(
    operation: NssOperation,
    module: NssModule,
) -> Result<*mut libc::c_void, crate::NssError> {
    let libraries = NSS_LIBRARIES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = libraries.lock().unwrap();

    // Load all functions for this module if not already loaded
    if let std::collections::hash_map::Entry::Vacant(e) = guard.entry(module) {
        let lib = load_all_functions_for_module(module)?;
        e.insert(lib);
    }

    // Return the specific function pointer
    let func_ptr = guard[&module].functions[operation.as_index()];
    if func_ptr.is_null() {
        return Err(crate::NssError::LibraryError(
            format!("Function {} not found in {}", operation.function_name(), module.name())
        ));
    }

    Ok(func_ptr)
}

/// Load a library and all its NSS function pointers upfront.
///
/// Note: Library handles are intentionally never closed with `dlclose()` as this
/// is standard practice for NSS modules and system libraries.
unsafe fn load_all_functions_for_module(module: NssModule) -> Result<NssLibrary, crate::NssError> {
    // Load the library once
    let lib_path = CString::new(module.path())
        .map_err(|_| crate::NssError::InvalidUtf8)?;

    let handle = dlopen(lib_path.as_ptr(), RTLD_LAZY);
    if handle.is_null() {
        return Err(crate::NssError::LibraryError(
            format!("Failed to load library: {}", module.path())
        ));
    }

    // Load all 10 function pointers
    let mut functions = [std::ptr::null_mut(); 10];
    for &operation in &ALL_OPERATIONS {
        let func_name = format!("_nss_{}_{}", module.name(), operation.function_name());
        let func_name_c = CString::new(func_name)
            .map_err(|_| crate::NssError::InvalidUtf8)?;

        // Some functions may not exist in all modules, store null for missing ones
        let func_ptr = dlsym(handle, func_name_c.as_ptr());
        functions[operation.as_index()] = func_ptr;
    }

    Ok(NssLibrary { functions })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nss_return_code_from_int() {
        assert_eq!(NssReturnCode::from(-2), NssReturnCode::TryAgain);
        assert_eq!(NssReturnCode::from(-1), NssReturnCode::Unavail);
        assert_eq!(NssReturnCode::from(0), NssReturnCode::NotFound);
        assert_eq!(NssReturnCode::from(1), NssReturnCode::Success);
        assert_eq!(NssReturnCode::from(2), NssReturnCode::Return);
        assert_eq!(NssReturnCode::from(999), NssReturnCode::Unavail); // Default case
    }

    #[test]
    fn test_nss_module_paths() {
        assert_eq!(NssModule::Files.path(), FILES_NSS_PATH);
        assert_eq!(NssModule::Sss.path(), SSS_NSS_PATH);
        assert_eq!(NssModule::Winbind.path(), WINBIND_NSS_PATH);
    }

    #[test]
    fn test_nss_module_names() {
        assert_eq!(NssModule::Files.name(), "files");
        assert_eq!(NssModule::Sss.name(), "sss");
        assert_eq!(NssModule::Winbind.name(), "winbind");
    }

    #[test]
    fn test_nss_module_upper_names() {
        assert_eq!(NssModule::Files.upper_name(), "FILES");
        assert_eq!(NssModule::Sss.upper_name(), "SSS");
        assert_eq!(NssModule::Winbind.upper_name(), "WINBIND");
    }

    #[test]
    fn test_nss_operation_function_names() {
        assert_eq!(NssOperation::GetGrNam.function_name(), "getgrnam_r");
        assert_eq!(NssOperation::GetGrGid.function_name(), "getgrgid_r");
        assert_eq!(NssOperation::SetGrEnt.function_name(), "setgrent");
        assert_eq!(NssOperation::EndGrEnt.function_name(), "endgrent");
        assert_eq!(NssOperation::GetGrEnt.function_name(), "getgrent_r");
        assert_eq!(NssOperation::GetPwNam.function_name(), "getpwnam_r");
        assert_eq!(NssOperation::GetPwUid.function_name(), "getpwuid_r");
        assert_eq!(NssOperation::GetPwEnt.function_name(), "getpwent_r");
        assert_eq!(NssOperation::SetPwEnt.function_name(), "setpwent");
        assert_eq!(NssOperation::EndPwEnt.function_name(), "endpwent");
    }

    #[test]
    fn test_constants() {
        assert_eq!(NSS_MODULES_DIR, "/usr/lib/x86_64-linux-gnu");
        assert!(FILES_NSS_PATH.contains("libnss_files.so.2"));
        assert!(SSS_NSS_PATH.contains("libnss_sss.so.2"));
        assert!(WINBIND_NSS_PATH.contains("libnss_winbind.so.2"));
    }
}