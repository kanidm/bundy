#[derive(Debug)]
pub enum BundyError {
    InvalidSignature,
    InvalidAlgo,
    OpenSsl,
    JsonEncode,
    JsonDecode,
    Base64,
}
