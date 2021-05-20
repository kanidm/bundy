use crate::error::BundyError;
use crate::{Algo, Data};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rand::rand_bytes;
use openssl::sign::Signer;

use serde::de::DeserializeOwned;
use serde::Serialize;

use std::str::FromStr;

pub struct HS512 {
    k: PKey<Private>,
}

impl HS512 {
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
        let unverified: String = Data::parse_without_verification(&signed).unwrap();

        assert_eq!(data, verified);
        assert_eq!(data, unverified);
    }
}
