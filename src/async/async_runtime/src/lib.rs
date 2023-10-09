// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::boxed::Box;
use core::future::Future;
use core::task::Poll;
use executor::*;

pub mod executor;

pub fn run<T>(future: impl Future<Output = T> + 'static + Send) -> Poll<T>
where
    T: Send + 'static,
{
    DEFAULT_EXECUTOR.lock().run(Box::pin(future))
}

pub fn block_on<T>(future: impl Future<Output = T> + 'static + Send) -> T
where
    T: Send + 'static,
{
    DEFAULT_EXECUTOR.lock().block_on(Box::pin(future))
}

pub fn add_task<T>(future: impl Future<Output = T> + 'static + Send)
where
    T: Send + 'static,
{
    DEFAULT_EXECUTOR.lock().add_task(Box::pin(future))
}

// output: left?
pub fn poll_tasks() -> bool {
    DEFAULT_EXECUTOR.lock().poll_tasks()
}