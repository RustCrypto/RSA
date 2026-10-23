//! Single-threaded bump allocator for these short, independent analyses.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{addr_of_mut, null_mut};

const HEAP_SIZE: usize = 4096;

#[repr(align(64))]
struct Heap([u8; HEAP_SIZE]);

static mut HEAP: Heap = Heap([0; HEAP_SIZE]);
static mut NEXT: usize = 0;

struct Allocator;

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

// SAFETY: Each analysis is single-threaded. Allocations are disjoint, aligned,
// and remain valid until reset, which is called before any allocation.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() > align_of::<Heap>() {
            return null_mut();
        }

        // SAFETY: Only the current single-threaded analysis accesses NEXT.
        let start = unsafe { (NEXT + layout.align() - 1) & !(layout.align() - 1) };
        let Some(end) = start.checked_add(layout.size()) else {
            return null_mut();
        };
        if end > HEAP_SIZE {
            return null_mut();
        }

        // SAFETY: The allocation is aligned and within HEAP; advancing NEXT
        // prevents overlap with earlier allocations.
        unsafe {
            NEXT = end;
            addr_of_mut!(HEAP.0).cast::<u8>().add(start)
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

/// Initialize the cursor explicitly: BINSEC starts at each checkct entrypoint,
/// without running startup code or initializing .bss.
///
/// # Safety
/// No allocation may be live, and no other thread may access the allocator.
pub unsafe fn reset() {
    // SAFETY: Guaranteed by the caller.
    unsafe { NEXT = 0 };
}
