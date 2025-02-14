/*
 *  Onenote document parser to extract embedded files.
 *
 *  Copyright (C) 2023-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Micah Snyder
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

use std::{
    convert::TryInto,
    mem, panic,
    path::{Path, PathBuf},
};

use hex_literal::hex;
use log::{debug, error};
use onenote_parser;

/// Error enumerates all possible errors returned by this library.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid format")]
    Format,

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Failed to open file: {0}, {1}")]
    FailedToOpen(PathBuf, String),

    #[error("Failed to get size for file: {0}")]
    FailedToGetFileSize(PathBuf),

    #[error("{0} parameter is NULL")]
    NullParam(&'static str),

    #[error("No more files to extract")]
    NoMoreFiles,

    #[error("Unable to parse OneNote file")]
    Parse,

    #[error("Failed to parse OneNote file due to a panic in the onenote_parser library")]
    OneNoteParserPanic,
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Struct representing a file extracted from a OneNote document.
/// This has the option of providing a file name, if one was found when extracting the file.
pub struct ExtractedFile {
    pub name: Option<String>,
    pub data: Vec<u8>,
}

/// Struct used for a file handle for our OneNote parser.
/// This struct is used to keep track of state for our iterator to work through the document extracting each file.
/// There are three different ways we keep track of state depending on the file format and the way in which the file was opened.
#[derive(Default)]
pub struct OneNote<'a> {
    embedded_files: Vec<ExtractedFile>,
    remaining_vec: Option<Vec<u8>>,
    remaining: Option<&'a [u8]>,
}

// https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/8806fd18-6735-4874-b111-227b83eaac26
#[repr(packed)]
#[allow(dead_code)]
struct FileDataHeader {
    guid_header: [u8; 16],
    cb_length: u64,
    unused: u32,
    reserved: u64,
}
const SIZE_OF_FILE_DATA_HEADER: usize = mem::size_of::<FileDataHeader>();

// Hex sequence identifying the start of a file data store object.
const FILE_DATA_STORE_OBJECT: &[u8] = &hex!("e716e3bd65261145a4c48d4d0b7a9eac");

// Hex sequence identifying the start of a OneNote file.
const ONE_MAGIC: &[u8] = &hex!("e4525c7b8cd8a74daeb15378d02996d3");

impl<'a> OneNote<'a> {
    /// Open a OneNote document given a slice bytes.
    pub fn from_bytes(data: &'a [u8], filename: &Path) -> Result<OneNote<'a>, Error> {
        debug!(
            "Inspecting OneNote file for attachments from in-memory buffer of size {}-bytes named {}\n",
            data.len(), filename.to_string_lossy()
        );

        fn parse_section_buffer(data: &[u8], filename: &Path) -> Result<Vec<ExtractedFile>, Error> {
            let mut embedded_files: Vec<ExtractedFile> = vec![];
            let mut parser = onenote_parser::Parser::new();

            if let Ok(section) = parser.parse_section_buffer(data, filename) {
                // file appears to be OneStore 2.8 `.one` file.
                section.page_series().iter().for_each(|page_series| {
                    page_series.pages().iter().for_each(|page| {
                        page.contents().iter().for_each(|page_content| {
                            if let Some(page_outline) = page_content.outline() {
                                page_outline.items().iter().for_each(|outline_item| {
                                    outline_item.element().iter().for_each(|&outline_element| {
                                        outline_element.contents().iter().for_each(|content| {
                                            if let Some(embedded_file) = content.embedded_file() {
                                                let data = embedded_file.data();
                                                let name = embedded_file.filename();

                                                // If name is empty, set to None.
                                                let name = if name.is_empty() {
                                                    debug!("Found unnamed attached file of size {}-bytes", data.len());
                                                    None
                                                } else {
                                                    debug!("Found attached file '{}' of size {}-bytes", name, data.len());
                                                    Some(name.to_string())
                                                };

                                                embedded_files.push(ExtractedFile {
                                                    name,
                                                    data: data.to_vec(),
                                                });
                                            }
                                        });
                                    });
                                });
                            }
                        });
                    });
                });
            } else {
                return Err(Error::Parse);
            }

            Ok(embedded_files)
        }

        // Try to parse the section buffer using the onenote_parser crate.
        // Attempt to catch panics in case the parser encounter unexpected issues.
        let result_result = panic::catch_unwind(|| -> Result<Vec<ExtractedFile>, Error> {
            parse_section_buffer(data, filename)
        });

        // Check if it panicked. If no panic, grab the parse result.
        let result = result_result.map_err(|_| Error::OneNoteParserPanic)?;

        if let Ok(embedded_files) = result {
            // Successfully parsed the OneNote file with the onenote_parser crate.
            Ok(OneNote {
                embedded_files,
                ..Default::default()
            })
        } else {
            debug!("Unable to parse OneNote file with onenote_parser crate. Trying a different method known to work with older office 2010 OneNote files to extract attachments.");

            let embedded_files: Vec<ExtractedFile> = vec![];

            // Verify that the OneNote document file magic is correct.
            // We don't check this for the onenote_parser crate because it does this for us, and may add support for newer OneNote file formats in the future.
            let file_magic = data.get(0..16).ok_or(Error::Format)?;
            if file_magic != ONE_MAGIC {
                return Err(Error::Format);
            }

            Ok(OneNote {
                embedded_files,
                remaining: Some(data),
                ..Default::default()
            })
        }
    }

    /// Open a OneNote document given the document was provided as a slice of bytes.
    pub fn next_file(&mut self) -> Option<ExtractedFile> {
        debug!("Looking to extract file from OneNote section...");

        let mut file_data: Option<Vec<u8>> = None;

        let remaining = if let Some(remaining_in) = self.remaining {
            let remaining = if let Some(pos) = find_bytes(remaining_in, FILE_DATA_STORE_OBJECT) {
                let (_, remaining) = remaining_in.split_at(pos);
                // Found file data store object.
                remaining
            } else {
                return None;
            };

            let data_length = if let Some(x) = remaining.get(16..20) {
                u32::from_le_bytes(x.try_into().unwrap()) as u64
            } else {
                return None;
            };

            let data: &[u8] = remaining
                .get(SIZE_OF_FILE_DATA_HEADER..SIZE_OF_FILE_DATA_HEADER + data_length as usize)?;

            file_data = Some(data.to_vec());

            Some(&remaining[SIZE_OF_FILE_DATA_HEADER + (data_length as usize)..remaining.len()])
        } else {
            None
        };

        self.remaining = remaining;

        file_data.map(|data| ExtractedFile { data, name: None })
    }

    /// Get the next file from the OneNote document using the method required for when we've read the file into a Vec.
    pub fn next_file_vec(&mut self) -> Option<ExtractedFile> {
        debug!("Looking to extract file from OneNote section...");

        let mut file_data: Option<Vec<u8>> = None;

        self.remaining_vec = if let Some(ref remaining_vec) = self.remaining_vec {
            let remaining = if let Some(pos) = find_bytes(remaining_vec, FILE_DATA_STORE_OBJECT) {
                let (_, remaining) = remaining_vec.split_at(pos);
                // Found file data store object.
                remaining
            } else {
                return None;
            };

            let data_length = if let Some(x) = remaining.get(16..20) {
                u32::from_le_bytes(x.try_into().unwrap()) as u64
            } else {
                return None;
            };

            let data: &[u8] = remaining
                .get(SIZE_OF_FILE_DATA_HEADER..SIZE_OF_FILE_DATA_HEADER + data_length as usize)?;

            file_data = Some(data.to_vec());

            Some(Vec::from(
                &remaining[SIZE_OF_FILE_DATA_HEADER + (data_length as usize)..remaining.len()],
            ))
        } else {
            None
        };

        file_data.map(|data| ExtractedFile { data, name: None })
    }

    /// Get the next file from the OneNote document using the method required for the onenote_parser crate.
    pub fn next_file_parser(&mut self) -> Option<ExtractedFile> {
        self.embedded_files.pop()
    }
}

impl<'a> Iterator for OneNote<'a> {
    type Item = ExtractedFile;

    fn next(&mut self) -> Option<ExtractedFile> {
        // Find the next embedded file
        if self.remaining.is_some() {
            // Data stored in a slice.
            self.next_file()
        } else if self.remaining_vec.is_some() {
            // Data stored in a Vec.
            self.next_file_vec()
        } else if !self.embedded_files.is_empty() {
            // Data stored in a Vec.
            self.next_file_parser()
        } else {
            None
        }
    }
}
