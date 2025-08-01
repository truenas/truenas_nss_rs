use pyo3::prelude::*;
use pyo3::types::PyDict;
use libc::uid_t;
use crate::{PasswdEntry, PasswdIterator};
use crate::passwd::{getpwnam as rust_getpwnam, getpwuid as rust_getpwuid, iterpw as rust_iterpw};
use super::nss_common::PyNssModule;

#[pyclass]
#[derive(Debug, Clone)]
pub struct PyPasswdEntry {
    #[pyo3(get)]
    pub pw_name: String,
    #[pyo3(get)]
    pub pw_uid: uid_t,
    #[pyo3(get)]
    pub pw_gid: uid_t,
    #[pyo3(get)]
    pub pw_gecos: String,
    #[pyo3(get)]
    pub pw_dir: String,
    #[pyo3(get)]
    pub pw_shell: String,
    #[pyo3(get)]
    pub source: String,
}

#[pymethods]
impl PyPasswdEntry {
    fn __str__(&self) -> String {
        format!("{}:x:{}:{}:{}:{}:{}",
                self.pw_name, self.pw_uid, self.pw_gid,
                self.pw_gecos, self.pw_dir, self.pw_shell)
    }

    fn __repr__(&self) -> String {
        format!("PasswdEntry(name='{}', uid={}, gid={}, gecos='{}', dir='{}', shell='{}', source='{}')",
                self.pw_name, self.pw_uid, self.pw_gid,
                self.pw_gecos, self.pw_dir, self.pw_shell, self.source)
    }

    fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
        let dict = PyDict::new(py);
        dict.set_item("pw_name", &self.pw_name)?;
        dict.set_item("pw_uid", self.pw_uid)?;
        dict.set_item("pw_gid", self.pw_gid)?;
        dict.set_item("pw_gecos", &self.pw_gecos)?;
        dict.set_item("pw_dir", &self.pw_dir)?;
        dict.set_item("pw_shell", &self.pw_shell)?;
        dict.set_item("source", &self.source)?;
        Ok(dict.into())
    }
}

impl From<PasswdEntry> for PyPasswdEntry {
    fn from(entry: PasswdEntry) -> Self {
        PyPasswdEntry {
            pw_name: entry.pw_name,
            pw_uid: entry.pw_uid,
            pw_gid: entry.pw_gid,
            pw_gecos: entry.pw_gecos,
            pw_dir: entry.pw_dir,
            pw_shell: entry.pw_shell,
            source: entry.source,
        }
    }
}

#[pyclass]
pub struct PyPasswdIterator {
    inner: PasswdIterator,
}

#[pymethods]
impl PyPasswdIterator {
    fn __iter__(slf: PyRef<Self>) -> PyRef<Self> {
        slf
    }

    fn __next__(mut slf: PyRefMut<Self>) -> PyResult<Option<PyPasswdEntry>> {
        match slf.inner.next() {
            Some(Ok(entry)) => Ok(Some(entry.into())),
            Some(Err(e)) => Err(PyErr::from(e)),
            None => Ok(None),
        }
    }
}

impl From<PasswdIterator> for PyPasswdIterator {
    fn from(iterator: PasswdIterator) -> Self {
        PyPasswdIterator { inner: iterator }
    }
}

/// Return the password database entry for the given user by name.
///
/// Args:
///     name: Username to look up
///     module: NSS module from which to retrieve the user
///
/// Returns:
///     PyPasswdEntry: Password database entry
///
/// Raises:
///     KeyError: If the user is not found
#[pyfunction]
#[pyo3(signature = (name, *, module=None))]
pub fn getpwnam(py: Python<'_>, name: &str, module: Option<PyNssModule>) -> PyResult<PyPasswdEntry> {
    use pyo3::exceptions::PyKeyError;
    use crate::{NssError, NssReturnCode};

    let nss_module = module.map(|m| m.into());
    let result = py.allow_threads(|| rust_getpwnam(name, nss_module));
    match result {
        Ok(entry) => Ok(entry.into()),
        Err(NssError::NssOperationFailed { return_code: NssReturnCode::NotFound, .. }) => {
            Err(PyKeyError::new_err(format!("getpwnam(): name not found: '{}'", name)))
        },
        Err(e) => Err(PyErr::from(e)),
    }
}

/// Return the password database entry for the given user by uid.
///
/// Args:
///     uid: User ID to look up
///     module: NSS module from which to retrieve the user
///
/// Returns:
///     PyPasswdEntry: Password database entry
///
/// Raises:
///     KeyError: If the user is not found
#[pyfunction]
#[pyo3(signature = (uid, *, module=None))]
pub fn getpwuid(py: Python<'_>, uid: &Bound<'_, pyo3::PyAny>, module: Option<PyNssModule>) -> PyResult<PyPasswdEntry> {
    use pyo3::exceptions::{PyKeyError, PyOverflowError};
    use crate::{NssError, NssReturnCode};

    // Try to extract uid_t, convert OverflowError to KeyError
    let uid_val: uid_t = match uid.extract() {
        Ok(val) => val,
        Err(e) if e.is_instance_of::<PyOverflowError>(py) => {
            // OverflowError (e.g., negative values) - treat as not found
            return Err(PyKeyError::new_err(format!("getpwuid(): uid not found: '{}'", uid)));
        }
        Err(e) => return Err(e),
    };

    let nss_module = module.map(|m| m.into());
    let result = py.allow_threads(|| rust_getpwuid(uid_val, nss_module));
    match result {
        Ok(entry) => Ok(entry.into()),
        Err(NssError::NssOperationFailed { return_code: NssReturnCode::NotFound, .. }) => {
            Err(PyKeyError::new_err(format!("getpwuid(): uid not found: '{}'", uid)))
        },
        Err(e) => Err(PyErr::from(e)),
    }
}

/// Generator that yields password entries on server
///
/// Args:
///     module: NSS module from which to retrieve the entries
///
/// Returns:
///     PyPasswdIterator: Iterator over password database entries
///
/// Warning:
///     Users of this API should not create two generators for
///     same passwd database concurrently in the same thread due to NSS
///     modules storing the handle for the pwent in thread-local variable.
#[pyfunction]
#[pyo3(signature = (module=PyNssModule::FILES))]
pub fn iterpw(py: Python<'_>, module: PyNssModule) -> PyResult<PyPasswdIterator> {
    let nss_module = module.into();
    let iterator = py.allow_threads(|| rust_iterpw(nss_module));
    Ok(iterator.into())
}

/// Returns all password entries on server (similar to pwd.getpwall()).
///
/// Args:
///     module: NSS module from which to retrieve the entries
///     as_dict: return password database entries as dictionaries
///
/// Returns:
///     dict: Dictionary keyed by NSS module, e.g.
///           {'FILES': [<PyPasswdEntry>, <PyPasswdEntry>], 'WINBIND': [], 'SSS': []}
#[pyfunction]
#[pyo3(signature = (*, module=None, as_dict=false))]
pub fn getpwall(module: Option<PyNssModule>, as_dict: bool, py: Python<'_>) -> PyResult<PyObject> {
    use crate::passwd::getpwall as rust_getpwall;
    use pyo3::types::PyDict;

    // Convert PyNssModule option to NssModule option
    let nss_module = module.map(|m| m.into());

    let entries_result = py.allow_threads(|| rust_getpwall(nss_module));
    match entries_result {
        Ok(entries) => {
            if as_dict {
                // Return dictionary keyed by uppercase module name
                let result_dict = PyDict::new(py);
                let mut entries_by_module: std::collections::HashMap<String, Vec<PyPasswdEntry>> = std::collections::HashMap::new();

                for entry in entries {
                    let source = entry.source.to_uppercase();
                    let py_entry = PyPasswdEntry::from(entry);
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
                // Return dictionary keyed by uppercase module name with PyPasswdEntry objects
                let result_dict = PyDict::new(py);
                let mut entries_by_module: std::collections::HashMap<String, Vec<PyPasswdEntry>> = std::collections::HashMap::new();

                for entry in entries {
                    let source = entry.source.to_uppercase();
                    let py_entry = PyPasswdEntry::from(entry);
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
    m.add_class::<PyPasswdEntry>()?;
    m.add_class::<PyPasswdIterator>()?;
    m.add_function(wrap_pyfunction!(getpwnam, m)?)?;
    m.add_function(wrap_pyfunction!(getpwuid, m)?)?;
    m.add_function(wrap_pyfunction!(iterpw, m)?)?;
    m.add_function(wrap_pyfunction!(getpwall, m)?)?;
    Ok(())
}
