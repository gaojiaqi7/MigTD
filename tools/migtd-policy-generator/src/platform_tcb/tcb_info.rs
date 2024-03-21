// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Result};
use serde::Deserialize;

use crate::fetch_data_from_url;

const TCB_INFO_URL: &str = "https://api.trustedservices.intel.com/tdx/certification/v4/tcb";
const SBX_TCB_INFO_URL: &str = "https://sbx.api.trustedservices.intel.com/tdx/certification/v4/tcb";

pub async fn fetch_platform_tcb(for_production: bool, fmspc: &str) -> Result<Option<PlatformTcb>> {
    let tcb_info_url = if for_production {
        TCB_INFO_URL
    } else {
        SBX_TCB_INFO_URL
    };
    let url = format!("{}?fmspc={}", tcb_info_url, fmspc);
    match fetch_data_from_url(&url).await {
        Ok(data) => {
            println!("Got TCB info of fmspc - {}", fmspc,);
            Ok(Some(serde_json::from_slice::<PlatformTcb>(&data)?))
        }
        Err(response_code) => {
            if response_code == 404 {
                // Ignore 404 errors
                Ok(None)
            } else {
                eprintln!(
                    "Error fetching details for fmspc {}: {:?}",
                    fmspc, response_code
                );
                Err(anyhow!("FetchTcbInfo"))
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformTcb {
    pub tcb_info: TcbInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    pub fmspc: String,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_status: String,
}

#[derive(Debug, Deserialize)]
pub struct Tcb {
    pub sgxtcbcomponents: Vec<Svn>,
    pub pcesvn: u64,
    pub tdxtcbcomponents: Vec<Svn>,
}

impl Tcb {
    pub fn get_sgx_tcb(&self) -> Vec<u8> {
        self.sgxtcbcomponents.iter().map(|svn| svn.svn).collect()
    }

    pub fn get_tdx_tcb(&self) -> Vec<u8> {
        self.tdxtcbcomponents.iter().map(|svn| svn.svn).collect()
    }
}

#[derive(Debug, Deserialize)]
pub struct Svn {
    svn: u8,
}

mod test {
    #[test]
    fn test_deserialize() {
        use super::PlatformTcb;

        let example = include_str!("../../test/tcb_info.json");
        let result = serde_json::from_str::<PlatformTcb>(example);
        assert!(result.is_ok());
    }
}
