use pyo3::prelude::*;
use pyo3::exceptions::PyException;
use crate::{NssError as RustNssError, NssModule};

#[pyclass]
#[derive(Debug, Clone)]
pub struct PyNssModule {
    inner: NssModule,
}

#[pymethods]
impl PyNssModule {
    #[new]
    fn new(name: &str) -> PyResult<Self> {
        let module = match name.to_lowercase().as_str() {
            "files" => NssModule::Files,
            "sss" => NssModule::Sss,
            "winbind" => NssModule::Winbind,
            _ => return Err(NssError::new_err(format!("Unknown NSS module: {}", name))),
        };
        Ok(PyNssModule { inner: module })
    }

    fn __str__(&self) -> String {
        self.inner.name().to_string()
    }

    fn __repr__(&self) -> String {
        format!("NssModule('{}')", self.inner.name())
    }

    #[getter]
    fn name(&self) -> String {
        self.inner.name().to_string()
    }

    #[classattr]
    pub const FILES: PyNssModule = PyNssModule { inner: NssModule::Files };

    #[classattr]
    pub const SSS: PyNssModule = PyNssModule { inner: NssModule::Sss };

    #[classattr]
    pub const WINBIND: PyNssModule = PyNssModule { inner: NssModule::Winbind };
}

impl From<NssModule> for PyNssModule {
    fn from(module: NssModule) -> Self {
        PyNssModule { inner: module }
    }
}

impl From<PyNssModule> for NssModule {
    fn from(py_module: PyNssModule) -> Self {
        py_module.inner
    }
}

pyo3::create_exception!(truenas_nss, NssError, PyException);

impl From<RustNssError> for PyErr {
    fn from(err: RustNssError) -> Self {
        NssError::new_err(err.to_string())
    }
}

pub fn init_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyNssModule>()?;
    m.add("NssError", m.py().get_type::<NssError>())?;
    Ok(())
}