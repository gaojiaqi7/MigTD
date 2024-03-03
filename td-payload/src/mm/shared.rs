// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::{alloc::Layout, ptr::NonNull};
use linked_list_allocator::LockedHeap;

use super::SIZE_4K;
use crate::arch::shared::decrypt;

static SHARED_MEMORY_ALLOCATOR: LockedHeap = LockedHeap::empty();
static PRIVATE_SHADOW_ALLOCATOR: LockedHeap = LockedHeap::empty();

pub fn init_shared_memory(start: u64, size: usize) {
    let shadow_size = size / 2;
    let shared_start = start + shadow_size as u64;
    let shared_size = size - shadow_size;

    // Set the shared memory region to be shared
    decrypt(shared_start, shared_size);
    // Initialize the shared memory allocator
    unsafe {
        SHARED_MEMORY_ALLOCATOR
            .lock()
            .init(shared_start as *mut u8, shared_size);
        PRIVATE_SHADOW_ALLOCATOR
            .lock()
            .init(start as *mut u8, shadow_size);
    }
}

pub struct SharedMemory {
    addr: usize,
    shadow_addr: usize,
    size: usize,
}

impl SharedMemory {
    pub fn new(num_page: usize) -> Option<Self> {
        let addr = unsafe { alloc_shared_pages(num_page)? };
        let shadow_addr = unsafe { alloc_private_shadow_pages(num_page)? };

        Some(Self {
            addr,
            shadow_addr,
            size: num_page * SIZE_4K,
        })
    }

    pub fn copy_to_private_shadow(&mut self) -> &[u8] {
        let shadow =
            unsafe { core::slice::from_raw_parts_mut(self.shadow_addr as *mut u8, self.size) };
        shadow.copy_from_slice(self.as_bytes());

        shadow
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.addr as *const u8, self.size) }
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.addr as *mut u8, self.size) }
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        unsafe { free_private_shadow_pages(self.addr, self.size / SIZE_4K) }
        unsafe { free_shared_pages(self.addr, self.size / SIZE_4K) }
    }
}

/// # Safety
/// The caller needs to explicitly call the `free_shared_pages` function after use
pub unsafe fn alloc_shared_pages(num: usize) -> Option<usize> {
    allocator_alloc(&SHARED_MEMORY_ALLOCATOR, num)
}

/// # Safety
/// The caller needs to explicitly call the `free_shared_page` function after use
pub unsafe fn alloc_shared_page() -> Option<usize> {
    alloc_shared_pages(1)
}

/// # Safety
/// The caller needs to ensure the correctness of the addr and page num
pub unsafe fn free_shared_pages(addr: usize, num: usize) {
    allocator_free(&SHARED_MEMORY_ALLOCATOR, addr, num)
}

/// # Safety
/// The caller needs to ensure the correctness of the addr
pub unsafe fn free_shared_page(addr: usize) {
    free_shared_pages(addr, 1)
}

/// # Safety
/// The caller needs to explicitly call the `free_private_shadow_pages` function after use
unsafe fn alloc_private_shadow_pages(num: usize) -> Option<usize> {
    allocator_alloc(&PRIVATE_SHADOW_ALLOCATOR, num)
}

/// # Safety
/// The caller needs to ensure the correctness of the addr and page num
unsafe fn free_private_shadow_pages(addr: usize, num: usize) {
    allocator_free(&PRIVATE_SHADOW_ALLOCATOR, addr, num)
}

unsafe fn allocator_alloc(allocator: &LockedHeap, num: usize) -> Option<usize> {
    let size = SIZE_4K.checked_mul(num)?;

    let addr = allocator
        .lock()
        .allocate_first_fit(Layout::from_size_align(size, SIZE_4K).ok()?)
        .map(|ptr| ptr.as_ptr() as usize)
        .ok()?;

    core::slice::from_raw_parts_mut(addr as *mut u8, size).fill(0);

    Some(addr)
}

unsafe fn allocator_free(allocator: &LockedHeap, addr: usize, num: usize) {
    let size = SIZE_4K.checked_mul(num).expect("Invalid page num");

    allocator.lock().deallocate(
        NonNull::new(addr as *mut u8).unwrap(),
        Layout::from_size_align(size, SIZE_4K).unwrap(),
    );
}
