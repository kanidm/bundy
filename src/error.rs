//! Errors that can be raised by the Bundy library

/// Errors that can be raised by the Bundy library
#[derive(Debug)]
pub enum BundyError {
    /// The signature of this token/blob is invalid, and may indicate attempted comromise.
    InvalidSignature,
    /// The algorithm of this token/blob does not match the verifier in use.
    InvalidAlgo,
    /// An error in the OpenSSL library has occured, and the procedure can not proceed.
    OpenSsl,
    /// The type failed to encode into json.
    JsonEncode,
    /// The type failed to decode into json, indicating some corruption.
    JsonDecode,
    /// The type failed to decode from base64, indicating some corruption.
    Base64,
}
