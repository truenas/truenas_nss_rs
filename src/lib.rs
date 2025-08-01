
pub mod error;
pub mod nss_common;
pub mod passwd;
pub mod group;

#[cfg(feature = "python")]
pub mod python_bindings;

pub use error::{NssError, NssResult};
pub use nss_common::{NssModule, NssOperation, NssReturnCode};
pub use passwd::{PasswdEntry, PasswdIterator, getpwnam, getpwuid, getpwall, iterpw};
pub use group::{GroupEntry, GroupIterator, getgrnam, getgrgid, getgrall, itergrp};

#[cfg(feature = "python")]
use pyo3::prelude::*;

/// Python bindings for TrueNAS Rust NSS library
#[cfg(feature = "python")]
#[pymodule]
fn truenas_nss(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Add the nss_common submodule
    let nss_common_module = PyModule::new(_py, "nss_common")?;
    python_bindings::nss_common::init_module(&nss_common_module)?;
    m.add_submodule(&nss_common_module)?;

    // Add the pwd submodule
    let pwd_module = PyModule::new(_py, "pwd")?;
    python_bindings::pwd::init_module(&pwd_module)?;
    m.add_submodule(&pwd_module)?;

    // Add the grp submodule
    let grp_module = PyModule::new(_py, "grp")?;
    python_bindings::grp::init_module(&grp_module)?;
    m.add_submodule(&grp_module)?;

    Ok(())
}