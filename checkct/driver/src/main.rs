#![no_std]
#![no_main]

#[macro_use]
extern crate alloc;

mod allocator;
mod driver;
// BINSEC 0.11.3 does not decode the RISC-V amoadd.w used by Arc::clone.
#[cfg(not(target_arch = "riscv32"))]
mod raw_rsa;

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
