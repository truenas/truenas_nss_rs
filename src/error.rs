use thiserror::Error;
use crate::nss_common::{NssReturnCode, NssOperation, NssModule};

pub type NssResult<T> = Result<T, NssError>;

#[derive(Error, Debug)]
pub enum NssError {
    #[error("NSS operation {operation:?} failed with errno {errno}: {return_code:?} on module [{module:?}]")]
    NssOperationFailed {
        errno: u32,
        operation: NssOperation,
        return_code: NssReturnCode,
        module: NssModule,
    },
    #[error("Buffer too small, need {needed} bytes")]
    BufferTooSmall { needed: usize },
    #[error("Invalid UTF-8 string")]
    InvalidUtf8,
    #[error("Null pointer encountered")]
    NullPointer,
    #[error("Library loading error: {0}")]
    LibraryError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nss_error_display() {
        let error = NssError::NssOperationFailed {
            errno: 2,
            operation: NssOperation::GetPwNam,
            return_code: NssReturnCode::NotFound,
            module: NssModule::Files,
        };

        let error_str = error.to_string();
        assert!(error_str.contains("GetPwNam"));
        assert!(error_str.contains("NotFound"));
        assert!(error_str.contains("Files"));
        assert!(error_str.contains("errno 2"));
    }

    #[test]
    fn test_buffer_too_small_error() {
        let error = NssError::BufferTooSmall { needed: 2048 };
        assert_eq!(error.to_string(), "Buffer too small, need 2048 bytes");
    }

    #[test]
    fn test_invalid_utf8_error() {
        let error = NssError::InvalidUtf8;
        assert_eq!(error.to_string(), "Invalid UTF-8 string");
    }

    #[test]
    fn test_library_error() {
        let error = NssError::LibraryError("Failed to load libnss_files.so.2".to_string());
        assert_eq!(error.to_string(), "Library loading error: Failed to load libnss_files.so.2");
    }
}