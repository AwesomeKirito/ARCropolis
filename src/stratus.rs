use std::fs;
use std::fs::File;
use std::io::Write;
use std::sync::Mutex;

use skyline::nn;

use crate::log;

use crate::hashes::*;

use crate::replacement_files::{ARC_FILES, STREAM_FILES};
use crate::resource::{DirectoryOffset, LoadedTables, ResServiceState, SubFile};

lazy_static::lazy_static! {
    pub static ref STRATUS : Mutex<Stratus> = Mutex::new(Stratus::new());
}

#[macro_export]
macro_rules! stratus {
    () => {
        STRATUS.lock().unwrap()
    };
}

unsafe impl Sync for Stratus {}

pub struct Stratus {
    pub incoming_read: bool,
    pub incoming_inflate: bool,
    pub incoming_load_type: LoadingType,
    pub previous_dir_entry: u32,
    pub individual_ctx: IndividualCtx,
    pub directory_ctx: DirectoryCtx,
}

impl Stratus {
    pub fn new() -> Self {
        Stratus {
            incoming_read: false,
            incoming_inflate: false,
            incoming_load_type: LoadingType::Directory,
            previous_dir_entry: 0,
            individual_ctx: IndividualCtx::new(),
            directory_ctx: DirectoryCtx::new(),
        }
    }

    pub fn handle_incoming_file(&mut self, t1_index: u32) {
        let mut context = IndividualCtx::new();

        let loaded_tables = LoadedTables::get_instance();
        let hash = loaded_tables.get_hash_from_t1_index(t1_index).as_u64();

        if let Some(path) = ARC_FILES.get_from_hash(hash) {
            context.t1_index = t1_index;
            context.file = fs::read(path).unwrap();

            println!(
                "[ARC::Stratus] Preparing to replace {}",
                crate::hashes::get(hash).unwrap_or(&"Unknown")
            );

            // Backup the subfile for use in ResService::InflateThreadMain
            let subfile = loaded_tables.get_arc().get_subfile_by_t1_index(t1_index);
            context.original_subfile = *subfile;

            // Patch the sizes
            subfile.compressed_size = context.file.len() as u32;
            subfile.decompressed_size = context.file.len() as u32;
            // Remove compressed flag
            // TODO: Use a constant
            subfile.flags &= !0x3;

            self.individual_ctx = context;
            self.incoming_read = true;
            self.incoming_load_type = LoadingType::File;
        }
    }

    pub fn handle_incoming_directory(
        &mut self,
        directory_offset: *const DirectoryOffset,
        dir_list_idx: u32,
        file_start_idx: u32,
        file_count: u32,
    ) {
        let context = &mut self.directory_ctx;

        // This has already been dealt with
        if self.previous_dir_entry == dir_list_idx {
            return;
        }

        let arc = LoadedTables::get_instance().get_arc();

        let pre_dir = arc.get_directory_list_by_index(context.pre_dir_list_idx);
        let post_dir = arc.get_directory_list_by_index(dir_list_idx);

        for i in
            post_dir.file_info_start_idx..(post_dir.file_info_start_idx + post_dir.file_info_count)
        {
            let file_info = arc.lookup_file_information_by_t1_index(i);
            context.upcoming_files.push(file_info.path_index);

            let hash = LoadedTables::get_instance()
                .get_hash_from_t1_index(file_info.path_index)
                .as_u64();

            println!(
                "[ARC::Stratus] Preparing to process {}",
                crate::hashes::get(hash).unwrap_or(&"Unknown")
            );
        }

        self.incoming_read = true;
        self.incoming_load_type = LoadingType::Directory;
    }

    pub fn handle_file_read(
        &mut self,
        handle: *const nn::fs::FileHandle,
        position: u64,
        data: *const skyline::libc::c_void,
        bytes_to_read: usize,
    ) -> ReadResult {
        if ResServiceState::get_instance().get_arc_handle() != handle {
            log!("[ARC::Stratus::FileRead] Different handle than expected.");
            return ReadResult::DifferentHandle;
        }

        if !self.incoming_read {
            return ReadResult::NoIncomingRead;
        }

        match self.incoming_load_type {
            LoadingType::Directory => return ReadResult::Directory,
            LoadingType::File => {
                let context = &mut self.individual_ctx;

                unsafe {
                    let mut data_slice =
                        std::slice::from_raw_parts_mut(data as *mut u8, bytes_to_read);
                    data_slice.write(&context.file[context.bytes_read..]);
                }

                context.bytes_read += bytes_to_read;

                // Is the file fully read?
                if context.bytes_read >= context.file.len() {
                    println!("[ARC::Stratus] Finished replacing");
                    self.incoming_read = false;
                    self.incoming_inflate = true;
                }

                return ReadResult::Layered;
            }
        }

        self.incoming_read = false;
        ReadResult::NoIncomingRead
    }

    pub fn handle_lookup_directory(
        &mut self,
        dir_list_idx: u32,
        load_type: u32,
        other_dir_list_idx: u32,
    ) {
        let context = &mut self.directory_ctx;

        context.pre_dir_list_idx = dir_list_idx;
        context.pre_load_type = load_type;
        context.pre_unk_dir_list_idx = other_dir_list_idx;
    }

    pub fn handle_inflate_thread_loop(&mut self) {
        if !self.incoming_inflate {
            return;
        }

        match self.incoming_load_type {
            LoadingType::File => {
                let context = &self.individual_ctx;

                let subfile = LoadedTables::get_instance()
                    .get_arc()
                    .get_subfile_by_t1_index(context.t1_index);
                // Restore the original subfile
                *subfile = context.original_subfile;
            }
            _ => {}
        }

        self.incoming_inflate = false;
    }
}

#[derive(Copy, Clone, Debug)]
pub enum LoadingType {
    Directory = 0,
    File = 4,
}

#[derive(Copy, Clone, Debug)]
pub enum ReadResult {
    DifferentHandle,
    NoIncomingRead,
    Directory,
    Layered,
}

pub struct IndividualCtx {
    pub t1_index: u32,
    pub file: Vec<u8>,
    pub file_size: usize,
    pub bytes_read: usize,
    pub original_subfile: SubFile,
}

impl IndividualCtx {
    pub fn new() -> Self {
        IndividualCtx {
            t1_index: 0,
            file: Vec::<u8>::new(),
            file_size: 0,
            bytes_read: 0,
            original_subfile: SubFile {
                offset: 0,
                compressed_size: 0,
                decompressed_size: 0,
                flags: 0,
            },
        }
    }
}

pub struct DirectoryCtx {
    pub pre_dir_list_idx: u32,
    pub pre_load_type: u32,
    pub pre_unk_dir_list_idx: u32,
    pub upcoming_files: Vec<u32>,
}

impl DirectoryCtx {
    pub fn new() -> Self {
        DirectoryCtx {
            pre_dir_list_idx: 0,
            pre_load_type: 0,
            pre_unk_dir_list_idx: 0,
            upcoming_files: Vec::<u32>::new(),
        }
    }
}
