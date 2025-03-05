mod mixnet_client;
use mixnet_client::MixnetHandler;
use pyo3::prelude::*;
use pyo3_asyncio::tokio::future_into_py;
use std::sync::Arc;

#[pyclass]
struct PyMixnetClient {
    inner: Arc<MixnetHandler>,
}

#[pymethods]
impl PyMixnetClient {
    /// Create a new Mixnet client asynchronously.
    #[staticmethod]
    fn create(py: Python) -> PyResult<&PyAny> {
        future_into_py(py, async {
            let client = MixnetHandler::new().await.map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("Client init failed: {:?}", e))
            })?;
            Ok(PyMixnetClient { inner: Arc::new(client) })
        })
    }

    /// Retrieve the client's Nym address.
    #[pyo3(name = "get_nym_address")]
    fn get_nym_address<'a>(&self, py: Python<'a>) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();
        future_into_py(py, async move {
            Ok(client.get_nym_address().await.unwrap_or_else(|| "Client disconnected".to_string()))
        })
    }

    /// Send a message through the Mixnet.
    #[pyo3(name = "send_message")]
    fn send_message<'a>(
        &self,
        py: Python<'a>,
        recipient: String,
        message: String,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();
        future_into_py(py, async move {
            client.send_message(&recipient, &message).await.map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to send message: {:?}", e))
            })?;
            Ok(())
        })
    }

    /// Start listening for incoming messages (ensures only one listener runs).
    #[pyo3(name = "receive_messages")]
    fn receive_messages<'a>(&self, py: Python<'a>) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();
        future_into_py(py, async move {
            client.receive_messages().await;
            Ok(())
        })
    }

    /// Set a callback function for incoming messages.
    #[pyo3(name = "set_message_callback")]
    fn set_message_callback<'a>(&self, py: Python<'a>, py_callback: PyObject) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();
        future_into_py(py, async move {
            client.set_callback(py_callback).await;
            Ok(())
        })
    }

    /// Shut down the client.
    #[pyo3(name = "shutdown")]
    fn shutdown<'a>(&self, py: Python<'a>) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();
        future_into_py(py, async move {
            client.disconnect().await;
            Ok(())
        })
    }
}

#[pymodule]
fn async_ffi(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyMixnetClient>()?;
    Ok(())
}

