// #![warn(missing_docs)]
#![warn(unused_extern_crates)]
#![deny(warnings)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[macro_use]
extern crate serde_derive;

pub mod error;
pub mod hs512;

use serde::de::DeserializeOwned;
use crate::error::BundyError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algo {
    HS512,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct Data {
    algo: Algo,
    sig: String,
    data: String,
    // sig: Vec<u8>,
    // data: Vec<u8>,
}

impl Data {
    pub fn parse_without_verification<T: DeserializeOwned>(input: &str) -> Result<T, BundyError> {
        let r_data = base64::decode_config(input, base64::URL_SAFE)
            .map_err(|e| {
                log::error!("{:?}", e);
                BundyError::Base64
            })?;

        let Data {
            algo: _, sig: _, data
        } = serde_json::from_slice(&r_data)
            .map_err(|e| {
                log::error!("{:?}", e);
                BundyError::JsonDecode
            })?;

        let data = base64::decode_config(&data, base64::URL_SAFE)
            .map_err(|e| {
                log::error!("{:?}", e);
                BundyError::Base64
            })?;

        serde_json::from_slice(&data)
            .map_err(|e| {
                log::error!("{:?}", e);
                BundyError::JsonDecode
            })
    }
}
