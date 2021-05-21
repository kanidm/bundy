#![warn(missing_docs)]
#![warn(unused_extern_crates)]
#![deny(warnings)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

//! Bundy provides the ability to sign and verify pieces of serialisable data in a way
//! that makes misusing it difficult. It is heavily inspired by `Fernet`. These transparent
//! data can be then inspected by clients for their content, while a server may verify that
//! they have not been tampered with.

#[macro_use]
extern crate serde_derive;

pub mod error;
pub mod hs512;

use crate::error::BundyError;
use serde::de::DeserializeOwned;

/// The algorithm used to create this data. This should NOT be trusted to be
/// correct, and only serves as a hint for the server for which algorithm may
/// be used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algo {
    /// Hmac with SHA512
    HS512,
}

/// A data package. This contains the algorithm, signature (in base64) and data (base64 json).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub struct Data {
    /// Algorithm in use to sign this data.
    algo: Algo,
    /// The base64 signature over data.
    sig: String,
    /// The base64 json.
    data: String,
}

impl Data {
    /// This allows a client to parse the content of a `Data` without the need to verify it's
    /// authenticity i.e. in the case an HMAC is used.
    ///
    /// # Safety
    /// This function is declared unsafe, as it allows a `Data` to be deserilised bypassing
    /// verification. You MUST understand the implications of using this function, and limit
    /// it to situations where verification is NOT required. Incorrect use of this function
    /// MAY cause security vulnerabilities in your application.
    pub unsafe fn parse_without_verification<T: DeserializeOwned>(
        input: &str,
    ) -> Result<T, BundyError> {
        let r_data = base64::decode_config(input, base64::URL_SAFE).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::Base64
        })?;

        let Data {
            algo: _,
            sig: _,
            data,
        } = serde_json::from_slice(&r_data).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::JsonDecode
        })?;

        let data = base64::decode_config(&data, base64::URL_SAFE).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::Base64
        })?;

        serde_json::from_slice(&data).map_err(|e| {
            log::error!("{:?}", e);
            BundyError::JsonDecode
        })
    }
}
