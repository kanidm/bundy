//! An implementation of HMAC with SHA512.

use crate::error::BundyError;
use crate::{Algo, Data};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rand::rand_bytes;
use openssl::sign::Signer;

use serde::de::DeserializeOwned;
use serde::Serialize;

use std::str::FromStr;

/// An instance of an HMAC SHA512 Signer and Verifier. This should only be needed on your server.
///
/// # Example
/// ```rust
/// use bundy::hs512::HS512;
/// use std::str::FromStr;
/// let pkey_str = HS512::generate_key().unwrap();
/// let hmac = HS512::from_str(&pkey_str).unwrap();
/// let data = "test_data".to_string();
/// // Sign the data, serialising it to a string.
/// let signed: String = hmac.sign(&data).unwrap();
/// // Verify the data, deserialising it from a string
/// let verified: String = hmac.verify(&signed).unwrap();
/// assert_eq!(data, verified);
/// ```
#[derive(Clone)]
pub struct HS512 {
    k: PKey<Private>,
}

impl HS512 {
    /// Generate a new HS512 key. This key may be stored and serialised for storage and
    /// future retrieval and persistance.
    ///
    /// This key is the root of the security of HMAC, and disclosure of it will allow ANY
    /// ONE to generate their own Data that appears to be valid. If it is disclosed, you MUST
    /// immediately reset and regenerate this key.
    pub fn generate_key() -> Result<String, BundyError> {
        let mut buf = [0; 32];
        rand_bytes(&mut buf).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::OpenSsl
        })?;

        // Can it become a pkey?
        let _ = PKey::hmac(&buf).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::OpenSsl
        })?;

        Ok(base64::encode_config(buf, base64::URL_SAFE))
    }

    /// Given a piece of Serialisable data of type `T`, sign and emit this as a base64'd blob.
    /// This base64 blob internally contains a `Data` type which is json encoded, and can be
    /// parsed by the `Data` api.
    ///
    /// The corresponding function for the server to do the reverse process of deserialise and
    /// verification is `verify`.
    pub fn sign<T: Serialize>(&self, data: &T) -> Result<String, BundyError> {
        let data = serde_json::to_vec(data).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::JsonEncode
        })?;

        let mut signer = Signer::new(MessageDigest::sha512(), &self.k).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::OpenSsl
        })?;

        let r = signer
            .sign_oneshot_to_vec(&data)
            .map_err(|e| {
                log::error!("{:?}", e);
                BundyError::OpenSsl
            })
            .map(|sig| Data {
                algo: Algo::HS512,
                sig: base64::encode_config(&sig, base64::URL_SAFE),
                data: base64::encode_config(&data, base64::URL_SAFE),
            })?;

        let r_data = serde_json::to_vec(&r).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::JsonEncode
        })?;

        Ok(base64::encode_config(r_data, base64::URL_SAFE))
    }

    /// Given an input blob, assert that this is a valid Bundy token, and verify the
    /// signature over data is valid and created by this instance of the HMAC. If it
    /// is not valid, the data is corrupted, or anyother possible error occurs, this
    /// will return an Error. Only in the `Ok(T)` state is the result considered valid
    /// and verified.
    pub fn verify<T: DeserializeOwned>(&self, input: &str) -> Result<T, BundyError> {
        // do we have a valid data blob?
        let r_data = base64::decode_config(input, base64::URL_SAFE).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::Base64
        })?;

        let Data { algo, sig, data } = serde_json::from_slice(&r_data).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::JsonDecode
        })?;

        let sig = base64::decode_config(&sig, base64::URL_SAFE).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::Base64
        })?;

        let data = base64::decode_config(&data, base64::URL_SAFE).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::Base64
        })?;

        if algo != Algo::HS512 {
            return Err(BundyError::InvalidAlgo);
        }

        let mut signer = Signer::new(MessageDigest::sha512(), &self.k).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::OpenSsl
        })?;

        let is_valid = signer
            .sign_oneshot_to_vec(&data)
            .map_err(|e| {
                log::error!("{:?}", e);
                BundyError::OpenSsl
            })
            .map(|dsig| dsig == sig)?;

        if !is_valid {
            return Err(BundyError::InvalidSignature);
        }

        // Thats it! Its valid, try and deserialise it.
        serde_json::from_slice(&data).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::JsonDecode
        })
    }
}

impl FromStr for HS512 {
    type Err = BundyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let buf = base64::decode_config(s, base64::URL_SAFE).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::Base64
        })?;

        PKey::hmac(&buf)
            .map_err(|e| {
                log::error!("{:?}", e);
                BundyError::OpenSsl
            })
            .map(|k| HS512 { k })
    }
}

#[cfg(test)]
mod tests {
    use super::HS512;
    use crate::Data;
    use std::str::FromStr;

    #[test]
    fn basic_test() {
        let _ = env_logger::builder().is_test(true).try_init();

        let pkey_str = HS512::generate_key().unwrap();
        log::debug!("{}", pkey_str);
        let hmac = HS512::from_str(&pkey_str).unwrap();

        let data = "test_data".to_string();

        let signed: String = hmac.sign(&data).unwrap();

        let verified: String = hmac.verify(&signed).unwrap();
        let unverified: String = unsafe { Data::parse_without_verification(&signed).unwrap() };

        assert_eq!(data, verified);
        assert_eq!(data, unverified);
    }
}
