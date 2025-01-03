use pyo3::prelude::*;

#[pymodule]
fn x3dh(_py: Python, m: &PyModule) -> PyResult<()> {
    #[pyfn(m, "generate_bundle")]
    fn generate_bundle(_py: Python) -> PyResult<String> {
        Ok("Hello, world!".to_string())
    }


    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
