// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use async_std::task::block_on;
use clap::Parser;
use migtd_policy_generator::policy::generate_policy;
use std::{fs, path::PathBuf, process::exit};

#[derive(Debug, Clone, Parser)]
struct Config {
    /// Set to use pre-prodution server. Production server is used by
    /// default.
    #[clap(long)]
    pub pre_production: bool,
    /// Where to write the generated policy
    #[clap(long, short)]
    pub output: PathBuf,
}

fn main() {
    let config = Config::parse();

    let policy = block_on(generate_policy(!config.pre_production)).unwrap_or_else(|e| {
        eprintln!("Failed to generate policy: {}", e);
        exit(1);
    });
    fs::write(config.output, &policy).unwrap_or_else(|e| {
        eprintln!("Failed to write output file: {}", e);
        exit(1);
    })
}

// async fn main() {
//     let uri = "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=80C06F000000";
//     let string: String = surf::get(uri).recv_string().await.unwrap();
//     println!("{}", string);
// }
