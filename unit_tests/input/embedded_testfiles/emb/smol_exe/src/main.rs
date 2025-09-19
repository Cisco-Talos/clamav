#![no_std]
#![no_main]

use core::arch::asm;

///
/// This is basically a Windows port of the example from: <https://darkcoding.net/software/a-very-small-rust-binary-indeed/>
/// With one minor change to print a message instead of only exiting with a code.
/// Thank you to the author.
///
/// Build with:
/// ```powershell
/// $env:RUSTFLAGS="-Ctarget-cpu=native -Clink-args=/ENTRY:_start -Clink-args=/SUBSYSTEM:CONSOLE -Clink-args=/LARGEADDRESSAWARE:NO -Clink-args=ucrt.lib -Crelocation-model=static -Clink-args=-Wl,-n,-N,--no-dynamic-linker,--no-pie,--build-id=none,--no-eh-frame-hdr"
/// cargo +nightly build  -Z build-std=std,panic_abort -Z build-std-features="optimize_for_size" --target x86_64-pc-windows-msvc  --release
/// ```
///

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let s = b"Lil EXE\n\0";
    unsafe {
        asm!(
            "mov rcx, {0}",
            "call puts",
            in(reg) s.as_ptr(),
            options(nostack, noreturn)
        )
        // nostack prevents `asm!` from push/pop rax
        // noreturn prevents it putting a 'ret' at the end
        //  but it does put a ud2 (undefined instruction) instead
    }
}

#[panic_handler]
fn my_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
