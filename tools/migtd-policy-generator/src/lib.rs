// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub mod platform_tcb;
pub mod policy;
pub mod qe_identity;

pub(crate) async fn fetch_data_from_url(url: &str) -> Result<Vec<u8>, u32> {
    match surf::get(url).recv_bytes().await {
        Ok(data) => Ok(data),
        Err(e) => Err(e.status() as u32),
    }
}
