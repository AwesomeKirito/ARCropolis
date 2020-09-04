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
use patching::RES_SERVICE_INITIALIZED_OFFSET;

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
fn begin_file_loading(ctx: &InlineCtx) {
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

#[hook(offset = 0x325d560, inline)]
fn begin_directory_loading(ctx: &InlineCtx) {
    unsafe {
        let directory_offset = *ctx.registers[28].x.as_ref() as *const DirectoryOffset;
        let dir_list_idx = *ctx.registers[22].w.as_ref();
        let file_idx_start = *ctx.registers[26].w.as_ref();
        let file_idx_count = *ctx.registers[19].w.as_ref();

        stratus!().handle_incoming_directory(
            directory_offset,
            dir_list_idx,
            file_idx_start,
            file_idx_count,
        );
    }
}

#[hook(offset = 0x325d390)]
fn load_directory_hook(
    res_service: &ResServiceState,
    file: &skyline::libc::c_void,
    dir_list_idx: u32,
    load_type: u32,
    other_dir_list_idx: u32,
) -> u32 {
    let arc = LoadedTables::get_instance().get_arc();

    match load_type {
        1 => {
            let dir_list = arc.get_directory_list_by_index(dir_list_idx);
            let dir_offset = arc.get_directory_offset_by_index(dir_list.full_path.index.as_u32());

            let redirect_dir_offset_idx = dir_offset.redirect_index;

            // Special case, to be ignored
            if redirect_dir_offset_idx == 0xFFFFFF {
                let flags = dir_list.flags >> 24;

                if (flags & 3) == 1 {
                    return 1;
                }
                else if (flags >> 4 & 1) != 0 {
                    let redirect_dir_offset = arc.get_directory_offset_by_index(redirect_dir_offset_idx);

                    if redirect_dir_offset.redirect_index == 0xFFFFFF {
                        return 0
                    }
                }
            }
        }
        _ => {}
    }

    stratus!().handle_lookup_directory(dir_list_idx, load_type, other_dir_list_idx);

    original!()(res_service, file, dir_list_idx, load_type, other_dir_list_idx)
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

#[hook(offset = RES_SERVICE_INITIALIZED_OFFSET, inline)]
fn resource_service_initialized(ctx: &InlineCtx) {
    // Patch filesizes in the Subfile table
    //patching::filesize_replacement();
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

    install_hooks!(
        resource_service_initialized,
        begin_file_loading,
        begin_directory_loading,
        file_read_hook,
        inflate_loop_hook
    );

    println!(
        "ARCropolis v{} - File replacement plugin is now installed",
        env!("CARGO_PKG_VERSION")
    );
}
