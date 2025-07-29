
pub mod error;
pub mod nss_common;
pub mod passwd;
pub mod group;

pub use error::{NssError, NssResult};
pub use nss_common::{NssModule, NssOperation, NssReturnCode};
pub use passwd::{PasswdEntry, PasswdIterator, getpwnam, getpwuid, getpwall, iterpw};
pub use group::{GroupEntry, GroupIterator, getgrnam, getgrgid, getgrall, itergrp};