// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::convert::TryInto;

use alloc::{collections::btree_map::BTreeMap, string::String, vec::Vec};
use crypto::x509::{self, AnyRef, Decode, DerResult, ObjectIdentifier, OctetStringRef, Reader};
use serde::{Deserialize, Serialize};

use crate::{
    parse_events,
    v2::{bytes_to_hex_string, verify_event_hash},
    EventName, PolicyError,
};

pub fn verify_collateral_integrity(
    collaterals: &[u8],
    event_log: &[u8],
) -> Result<(), PolicyError> {
    let events = parse_events(event_log).ok_or(PolicyError::InvalidEventLog)?;

    if !verify_event_hash(&events, &EventName::Collaterals, &collaterals)? {
        return Err(PolicyError::InvalidCollateral);
    }
    Ok(())
}

pub fn get_fmspc_from_quote(quote: &[u8]) -> Result<[u8; 6], PolicyError> {
    const PEM_CERT_BEGIN: &str = "-----BEGIN CERTIFICATE-----\n";
    const PEM_CERT_END: &str = "-----END CERTIFICATE-----\n";

    let mid = String::from_utf8_lossy(quote);
    let start_index = mid.find(PEM_CERT_BEGIN).ok_or(PolicyError::InvalidQuote)?;
    let end_index = mid.find(PEM_CERT_END).ok_or(PolicyError::InvalidQuote)? + PEM_CERT_END.len();

    let pck_cert = mid[start_index..end_index].as_bytes();
    let pck_der = crypto::pem_cert_to_der(pck_cert).map_err(|_| PolicyError::InvalidQuote)?;

    parse_fmspc_from_pck_cert(pck_der.as_ref())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InnerValue<'a> {
    pub id: ObjectIdentifier,
    pub value: Option<AnyRef<'a>>,
}

impl<'a> Decode<'a> for InnerValue<'a> {
    fn decode<R: Reader<'a>>(decoder: &mut R) -> DerResult<Self> {
        decoder.sequence(|decoder| {
            let id = decoder.decode()?;
            let value = decoder.decode()?;

            Ok(Self { id, value })
        })
    }
}

fn parse_fmspc_from_pck_cert(pck_der: &[u8]) -> Result<[u8; 6], PolicyError> {
    const PCK_FMSPC_EXTENSION_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1");
    const PCK_FMSPC_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.4");

    let x509 = x509::Certificate::from_der(pck_der).map_err(|_| PolicyError::InvalidQuote)?;
    let extensions = x509
        .tbs_certificate
        .extensions
        .ok_or(PolicyError::InvalidQuote)?;
    for ext in extensions.get() {
        if ext.extn_id == PCK_FMSPC_EXTENSION_OID {
            let vals = Vec::<InnerValue>::from_der(
                ext.extn_value.ok_or(PolicyError::InvalidQuote)?.as_bytes(),
            )
            .map_err(|_| PolicyError::InvalidQuote)?;
            for val in vals {
                if val.id == PCK_FMSPC_OID {
                    return val
                        .value
                        .ok_or(PolicyError::InvalidQuote)?
                        .decode_as::<OctetStringRef>()
                        .map_err(|_| PolicyError::InvalidQuote)?
                        .as_bytes()
                        .try_into()
                        .map_err(|_| PolicyError::InvalidQuote);
                }
            }
        }
    }
    Err(PolicyError::InvalidQuote)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Collateral {
    pub major_version: u16,
    pub minor_version: u16,
    pub tee_type: u32,
    pub pck_crl_issuer_chain: String,
    pub root_ca_crl: String,
    pub pck_crl: String,
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
}

impl Collateral {
    /// Read a Collateral instance from a byte slice.
    pub fn read_from_bytes(bytes: &[u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice(bytes).map_err(|_| PolicyError::InvalidCollateral)
    }
}

pub fn get_collateral_with_fmspc<'a>(
    fmspc: &[u8],
    collaterals: &'a [u8],
) -> Result<Collateral, PolicyError> {
    use serde_json::Value;

    // Parse as generic JSON value (minimal parsing)
    let json_map: BTreeMap<String, Value> =
        serde_json::from_slice(collaterals).map_err(|_| PolicyError::InvalidCollateral)?;

    let fmspc_key = bytes_to_hex_string(fmspc);

    // Get the specific collateral value and deserialize only that part
    let collateral_value = json_map
        .get(&fmspc_key)
        .ok_or(PolicyError::InvalidCollateral)?;

    // Deserialize only the target collateral
    serde_json::from_value(collateral_value.clone()).map_err(|_| PolicyError::InvalidCollateral)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformTcb {
    tcb_info: TcbInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    pub tcb_evaluation_data_number: u32,
}

pub fn get_tcb_evaluation_number_from_collateral(
    collateral: &Collateral,
) -> Result<u32, PolicyError> {
    let platform_tcb = serde_json::from_str::<PlatformTcb>(collateral.tcb_info.as_str())
        .map_err(|_| PolicyError::InvalidCollateral)?;
    Ok(platform_tcb.tcb_info.tcb_evaluation_data_number)
}

#[cfg(test)]
mod test {
    #[test]
    fn test_get_collateral_with_fmspc() {
        let fmspc = [0x30, 0x80, 0x6f, 0x00, 0x00, 0x00];
        let collaterals = include_bytes!("../../../../config/collateral_pre_production_fmspc.json");

        let result = super::get_collateral_with_fmspc(&fmspc, collaterals);
        assert!(result.is_ok());
    }
}
