#![feature(proc_macro_hygiene)]
#![feature(str_strip)]

use std::ffi::CStr;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::slice;

use skyline::hooks::InlineCtx;
use skyline::{hook, install_hooks, nn};

mod hashes;
mod patching;

mod replacement_files;
use replacement_files::{ARC_FILES, STREAM_FILES};

mod resource;
use resource::*;

mod stratus;
use stratus::{ReadResult, STRATUS};

mod config;
use config::CONFIG;

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        // Uncomment to enable logging
        if crate::config::CONFIG.misc.debug {
            println!($($arg)*);
        }
    };
}

#[hook(offset = 0x325b8e8, inline)]
fn begin_loading(ctx: &InlineCtx) {
    unsafe {
        let t1_index = *ctx.registers[25].w.as_ref();
        let hash = LoadedTables::get_instance()
            .get_hash_from_t1_index(t1_index)
            .as_u64();
        let internal_filepath = hashes::get(hash).unwrap_or(&"Unknown");

        println!(
            "[ARC::Loading | #{}] File path: {}, Hash: {}",
            t1_index, internal_filepath, hash,
        );

        if t1_index == 0xFFFFFF {
            return;
        }

        stratus!().handle_incoming_file(t1_index);
    };
}

#[hook(replace = nn::fs::ReadFile2)]
fn file_read_hook(
    handle: *const nn::fs::FileHandle,
    position: u64,
    data: *const skyline::libc::c_void,
    buffer_size: usize,
) -> u32 {
    match stratus!().handle_file_read(handle, position, data, buffer_size) {
        ReadResult::Layered => 0,
        _ => original!()(handle, position, data, buffer_size),
    }
}

#[hook(offset = 0x325c1b0, inline)]
fn inflate_loop_hook(ctx: &InlineCtx) {
    stratus!().handle_inflate_thread_loop();
}

#[skyline::main(name = "arcropolis")]
pub fn main() {
    // Read the configuration so we can set the filepaths
    lazy_static::initialize(&CONFIG);
    lazy_static::initialize(&ARC_FILES);
    lazy_static::initialize(&STREAM_FILES);
    lazy_static::initialize(&STRATUS);

    // Load hashes from rom:/skyline/hashes.txt if the file is present
    hashes::init();
    // Look for the offset of the various functions to hook
    patching::search_offsets();

    // This is a personal request, don't mind it too much.
    if let Some(_) = CONFIG.misc.mowjoh {
        skyline::error::show_error(69, "I'm Mowjoh!", "No really, he is.");
    }

    install_hooks!(begin_loading, file_read_hook, inflate_loop_hook);

    println!(
        "ARCropolis v{} - File replacement plugin is now installed",
        env!("CARGO_PKG_VERSION")
    );
}
