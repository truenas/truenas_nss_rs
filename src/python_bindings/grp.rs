use pyo3::prelude::*;
use pyo3::types::PyDict;
use libc::gid_t;
use crate::{GroupEntry, GroupIterator};
use crate::group::{getgrnam as rust_getgrnam, getgrgid as rust_getgrgid, itergrp as rust_itergrp};
use super::nss_common::PyNssModule;

#[pyclass]
#[derive(Debug, Clone)]
pub struct PyGroupEntry {
    #[pyo3(get)]
    pub gr_name: String,
    #[pyo3(get)]
    pub gr_gid: gid_t,
    #[pyo3(get)]
    pub gr_mem: Vec<String>,
    #[pyo3(get)]
    pub source: String,
}

#[pymethods]
impl PyGroupEntry {
    fn __str__(&self) -> String {
        let members = self.gr_mem.join(",");
        format!("{}:x:{}:{}", self.gr_name, self.gr_gid, members)
    }

    fn __repr__(&self) -> String {
        format!("GroupEntry(name='{}', gid={}, members={:?}, source='{}')",
                self.gr_name, self.gr_gid, self.gr_mem, self.source)
    }

    fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
        let dict = PyDict::new(py);
        dict.set_item("gr_name", &self.gr_name)?;
        dict.set_item("gr_gid", self.gr_gid)?;
        dict.set_item("gr_mem", &self.gr_mem)?;
        dict.set_item("source", &self.source)?;
        Ok(dict.into())
    }
}

impl From<GroupEntry> for PyGroupEntry {
    fn from(entry: GroupEntry) -> Self {
        PyGroupEntry {
            gr_name: entry.gr_name,
            gr_gid: entry.gr_gid,
            gr_mem: entry.gr_mem,
            source: entry.source,
        }
    }
}

#[pyclass]
pub struct PyGroupIterator {
    inner: GroupIterator,
}

#[pymethods]
impl PyGroupIterator {
    fn __iter__(slf: PyRef<Self>) -> PyRef<Self> {
        slf
    }

    fn __next__(mut slf: PyRefMut<Self>) -> PyResult<Option<PyGroupEntry>> {
        match slf.inner.next() {
            Some(Ok(entry)) => Ok(Some(entry.into())),
            Some(Err(e)) => Err(PyErr::from(e)),
            None => Ok(None),
        }
    }
}

impl From<GroupIterator> for PyGroupIterator {
    fn from(iterator: GroupIterator) -> Self {
        PyGroupIterator { inner: iterator }
    }
}

/// Return the group database entry for the given group by name.
///
/// Args:
///     name: Group name to look up
///     module: NSS module from which to retrieve the group
///
/// Returns:
///     PyGroupEntry: Group database entry
///
/// Raises:
///     KeyError: If the group is not found
#[pyfunction]
#[pyo3(signature = (name, *, module=None))]
pub fn getgrnam(py: Python<'_>, name: &str, module: Option<PyNssModule>) -> PyResult<PyGroupEntry> {
    use pyo3::exceptions::PyKeyError;
    use crate::{NssError, NssReturnCode};

    let nss_module = module.map(|m| m.into());
    let result = py.allow_threads(|| rust_getgrnam(name, nss_module));
    match result {
        Ok(entry) => Ok(entry.into()),
        Err(NssError::NssOperationFailed { return_code: NssReturnCode::NotFound, .. }) => {
            Err(PyKeyError::new_err(format!("getgrnam(): name not found: '{}'", name)))
        },
        Err(e) => Err(PyErr::from(e)),
    }
}

/// Return the group database entry for the given group by gid.
///
/// Args:
///     gid: Group ID to look up
///     module: NSS module from which to retrieve the group
///
/// Returns:
///     PyGroupEntry: Group database entry
///
/// Raises:
///     KeyError: If the group is not found
#[pyfunction]
#[pyo3(signature = (gid, *, module=None))]
pub fn getgrgid(py: Python<'_>, gid: &Bound<'_, pyo3::PyAny>, module: Option<PyNssModule>) -> PyResult<PyGroupEntry> {
    use pyo3::exceptions::{PyKeyError, PyOverflowError};
    use crate::{NssError, NssReturnCode};

    // Try to extract gid_t, convert OverflowError to KeyError
    let gid_val: gid_t = match gid.extract() {
        Ok(val) => val,
        Err(e) if e.is_instance_of::<PyOverflowError>(py) => {
            // OverflowError (e.g., negative values) - treat as not found
            return Err(PyKeyError::new_err(format!("getgrgid(): gid not found: '{}'", gid)));
        }
        Err(e) => return Err(e),
    };

    let nss_module = module.map(|m| m.into());
    let result = py.allow_threads(|| rust_getgrgid(gid_val, nss_module));
    match result {
        Ok(entry) => Ok(entry.into()),
        Err(NssError::NssOperationFailed { return_code: NssReturnCode::NotFound, .. }) => {
            Err(PyKeyError::new_err(format!("getgrgid(): gid not found: '{}'", gid)))
        },
        Err(e) => Err(PyErr::from(e)),
    }
}

/// Generator that yields group entries on server
///
/// Args:
///     module: NSS module from which to retrieve the entries
///
/// Returns:
///     PyGroupIterator: Iterator over group database entries
///
/// Warning:
///     Users of this API should not create two generators for
///     same group database concurrently in the same thread due to NSS
///     modules storing the handle for the grent in thread-local variable.
#[pyfunction]
#[pyo3(signature = (module=PyNssModule::FILES))]
pub fn itergrp(py: Python<'_>, module: PyNssModule) -> PyResult<PyGroupIterator> {
    let nss_module = module.into();
    let iterator = py.allow_threads(|| rust_itergrp(nss_module));
    Ok(iterator.into())
}

/// Returns all group entries on server (similar to grp.getgrall()).
///
/// Args:
///     module: NSS module from which to retrieve the entries
///     as_dict: return group database entries as dictionaries
///
/// Returns:
///     dict: Dictionary keyed by NSS module, e.g.
///           {'FILES': [<PyGroupEntry>, <PyGroupEntry>], 'WINBIND': [], 'SSS': []}
#[pyfunction]
#[pyo3(signature = (*, module=None, as_dict=false))]
pub fn getgrall(module: Option<PyNssModule>, as_dict: bool, py: Python<'_>) -> PyResult<PyObject> {
    use crate::group::getgrall as rust_getgrall;
    use pyo3::types::PyDict;

    // Convert PyNssModule option to NssModule option
    let nss_module = module.map(|m| m.into());

    let entries_result = py.allow_threads(|| rust_getgrall(nss_module));
    match entries_result {
        Ok(entries) => {
            if as_dict {
                // Return dictionary keyed by uppercase module name
                let result_dict = PyDict::new(py);
                let mut entries_by_module: std::collections::HashMap<String, Vec<PyGroupEntry>> = std::collections::HashMap::new();

                for entry in entries {
                    let source = entry.source.to_uppercase();
                    let py_entry = PyGroupEntry::from(entry);
                    entries_by_module.entry(source).or_default().push(py_entry);
                }

                for (module_name, module_entries) in entries_by_module {
                    let py_entries: Vec<PyObject> = module_entries.into_iter()
                        .map(|entry| entry.to_dict(py))
                        .collect::<PyResult<Vec<_>>>()?;
                    result_dict.set_item(module_name, py_entries)?;
                }

                Ok(result_dict.into())
            } else {
                // Return dictionary keyed by uppercase module name with PyGroupEntry objects
                let result_dict = PyDict::new(py);
                let mut entries_by_module: std::collections::HashMap<String, Vec<PyGroupEntry>> = std::collections::HashMap::new();

                for entry in entries {
                    let source = entry.source.to_uppercase();
                    let py_entry = PyGroupEntry::from(entry);
                    entries_by_module.entry(source).or_default().push(py_entry);
                }

                for (module_name, module_entries) in entries_by_module {
                    let py_objects: Vec<PyObject> = module_entries.into_iter()
                        .map(|entry| Py::new(py, entry).unwrap().into_any())
                        .collect();
                    result_dict.set_item(module_name, py_objects)?;
                }

                Ok(result_dict.into())
            }
        }
        Err(e) => Err(PyErr::from(e)),
    }
}

pub fn init_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyGroupEntry>()?;
    m.add_class::<PyGroupIterator>()?;
    m.add_function(wrap_pyfunction!(getgrnam, m)?)?;
    m.add_function(wrap_pyfunction!(getgrgid, m)?)?;
    m.add_function(wrap_pyfunction!(itergrp, m)?)?;
    m.add_function(wrap_pyfunction!(getgrall, m)?)?;
    Ok(())
}