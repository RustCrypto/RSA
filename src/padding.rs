/// Available padding schemes.
#[derive(Debug, Clone, Copy)]
pub enum PaddingScheme {
    PKCS1v15,
    OAEP,
}
