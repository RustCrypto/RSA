#![no_std]
#![no_main]

#[macro_use]
extern crate alloc;

mod allocator;
mod driver;

// Compile the actual private helper without adding a public API for the harness.
pub use rsa::errors;
#[allow(dead_code)]
#[path = "../../../src/algorithms/pad.rs"]
mod pad;
mod rng;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    panic!()
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    __checkct_panic()
}

/// The analysis of a path stops when it reaches this function.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __checkct_panic() -> ! {
    loop {}
}
