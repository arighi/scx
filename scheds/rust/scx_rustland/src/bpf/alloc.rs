// Copyright (c) Andrea Righi <andrea.righi@canonical.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::alloc::{GlobalAlloc, Layout};
use std::cell::UnsafeCell;
use std::sync::{Mutex, MutexGuard};

/// scx_rustland: memory allocator.
///
/// RustLandAllocator is a very simple block-based memory allocator that uses a pre-alloated buffer
/// and an array to keep track of the blocks that are free or allocated.
///
/// The purpose of this allocator is to prevent the user-space sheduler from triggering page fault,
/// that could potentially introduce deadlocks when the system is under heavy load conditions.
///
/// Despite its simplicity it can be reasonably fast and effective to satisfy the memory requests
/// from the user-space scheduler, that typically performs allocations in small chunks of the same
/// size.

// Pre-allocate an area of 64MB, with a block size of 64 bytes, that should be reasonable enough to
// handle small regular allocations performed by the user-space scheduler without introducing too
// much fragmentation.
const ARENA_SIZE: usize = 64 * 1024 * 1024;
const BLOCK_SIZE: usize = 64;
const NUM_BLOCKS: usize = ARENA_SIZE / BLOCK_SIZE;

#[repr(C, align(4096))]
struct RustLandMemory {
    // Pre-allocated buffer.
    arena: UnsafeCell<[u8; ARENA_SIZE]>,
    // Allocation map, each slot represents a block in memory: true = allocated, false = free.
    allocation_map: Mutex<[bool; NUM_BLOCKS]>,
}

unsafe impl Sync for RustLandMemory {}

// Memory pool for the allocator.
static MEMORY: RustLandMemory = RustLandMemory {
    arena: UnsafeCell::new([0; ARENA_SIZE]),
    allocation_map: Mutex::new([false; NUM_BLOCKS]),
};

pub struct RustLandAllocator;

unsafe impl GlobalAlloc for RustLandAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(BLOCK_SIZE);
        let align = layout.align();

        // Find the first sequence of free blocks that can accommodate the requested size.
        let mut map_guard: MutexGuard<[bool; NUM_BLOCKS]> = MEMORY.allocation_map.lock().unwrap();
        let mut contiguous_blocks = 0;
        let mut start_block = None;

        for (index, &is_allocated) in map_guard.iter().enumerate() {
            if is_allocated {
                // Reset consecutive blocks count if an allocated block is encountered.
                contiguous_blocks = 0;
            } else {
                contiguous_blocks += 1;
                if contiguous_blocks * BLOCK_SIZE >= size {
                    // Found a sequence of free blocks that can accommodate the size.
                    start_block = Some(index + 1 - contiguous_blocks);
                    break;
                }
            }
        }

        match start_block {
            Some(start) => {
                // Mark the corresponding blocks as allocated.
                for i in start..start + contiguous_blocks {
                    map_guard[i] = true;
                }

                // Return a pointer to the aligned allocated block.
                let offset = start * BLOCK_SIZE;
                let aligned_offset = (offset + align - 1) & !(align - 1);

                MEMORY.arena.get().cast::<u8>().add(aligned_offset)
            }
            None => {
                // No contiguous block sequence found, just panic.
                //
                // NOTE: we want to panic here so that we can better detect when we run out of
                // memory, instead of returning a null_ptr that could potentially hide the real
                // problem.
                panic!("Out of memory");
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = layout.size();

        // Calculate the block index from the released pointer.
        let offset = ptr as usize - MEMORY.arena.get() as usize;
        let start_block = offset / BLOCK_SIZE;
        let end_block = (offset + size - 1) / BLOCK_SIZE + 1;

        // Update the allocation map for all blocks in the released range.
        let mut map_guard: MutexGuard<[bool; NUM_BLOCKS]> = MEMORY.allocation_map.lock().unwrap();
        for block_index in start_block..end_block {
            map_guard[block_index] = false;
        }
    }
}
