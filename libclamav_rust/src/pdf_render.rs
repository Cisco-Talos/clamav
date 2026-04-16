/*
 *  Render the first page of a PDF document as jpeg in a [u8].
 *
 *  Copyright (C) 2023 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

use image::{DynamicImage, ImageFormat};
use pdfium_render::prelude::*;
use std::io::Cursor;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PdfImageFuzzyHashConfig {
    pub render_mode: u32,
    pub dpi: u32,
    pub canvas_width: u32,
    pub canvas_height: u32,
    pub image_format: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct RenderedPdfImage {
    pub image_data: *mut u8,
    pub image_len: usize,
    pub image_type: crate::sys::cli_file_t,
}

pub const PDF_IMAGE_FUZZY_HASH_RENDER_MODE_DEFAULT: u32 = 0;
pub const PDF_IMAGE_FUZZY_HASH_RENDER_MODE_DPI: u32 = 1;
pub const PDF_IMAGE_FUZZY_HASH_RENDER_MODE_CANVAS: u32 = 2;
pub const PDF_IMAGE_FUZZY_HASH_IMAGE_FORMAT_PNG: u32 = 1;
pub const PDF_IMAGE_FUZZY_HASH_IMAGE_FORMAT_JPEG: u32 = 2;

#[derive(thiserror::Error, Debug)]
pub enum PdfRenderError {
    #[error("PDF Rendering error : {0}")]
    PDFRenderError(#[from] PdfiumError),

    #[error("PDF Rendering error : {0}")]
    ImageEncodeError(#[from] image::ImageError),

    #[error("PDF Rendering error : empty document")]
    PDFRenderEmpty,
}

impl Default for PdfImageFuzzyHashConfig {
    fn default() -> Self {
        Self {
            render_mode: PDF_IMAGE_FUZZY_HASH_RENDER_MODE_CANVAS,
            dpi: 0,
            canvas_width: 2000,
            canvas_height: 2000,
            image_format: PDF_IMAGE_FUZZY_HASH_IMAGE_FORMAT_PNG,
        }
    }
}

pub fn render(
    data: &[u8],
    config: Option<&PdfImageFuzzyHashConfig>,
) -> Result<DynamicImage, PdfRenderError> {
    //let pdfium = Pdfium::new(Pdfium::bind_to_system_library()?);
    let pdfium = Pdfium::new(Pdfium::bind_to_statically_linked_library()?);
    let document = pdfium.load_pdf_from_byte_slice(data, None)?;

    if document.pages().is_empty() {
        return Err(PdfRenderError::PDFRenderEmpty);
    }

    let config = config.copied().unwrap_or_default();
    let render_config = match config.render_mode {
        PDF_IMAGE_FUZZY_HASH_RENDER_MODE_DPI if config.dpi > 0 => {
            PdfRenderConfig::new().scale_page_by_factor(config.dpi as f32 / 72.0)
        }
        PDF_IMAGE_FUZZY_HASH_RENDER_MODE_CANVAS | PDF_IMAGE_FUZZY_HASH_RENDER_MODE_DEFAULT => {
            let canvas_width = if config.canvas_width > 0 {
                config.canvas_width
            } else {
                2000
            } as i32;
            let canvas_height = if config.canvas_height > 0 {
                config.canvas_height
            } else {
                2000
            } as i32;
            PdfRenderConfig::new().scale_page_to_display_size(canvas_width, canvas_height)
        }
        _ => PdfRenderConfig::new().scale_page_to_display_size(2000, 2000),
    };

    let image = document
        .pages()
        .first()?
        .render_with_config(&render_config)?
        .as_image();

    Ok(image)
}

pub fn render_to_image(
    data: &[u8],
    config: Option<&PdfImageFuzzyHashConfig>,
) -> Result<(Vec<u8>, crate::sys::cli_file_t), PdfRenderError> {
    let image = render(data, config)?;
    let config = config.copied().unwrap_or_default();
    let mut cursor = Cursor::new(Vec::new());
    let image_type = match config.image_format {
        PDF_IMAGE_FUZZY_HASH_IMAGE_FORMAT_JPEG => {
            image.write_to(&mut cursor, ImageFormat::Jpeg)?;
            crate::sys::cli_file_CL_TYPE_JPEG
        }
        _ => {
            image.write_to(&mut cursor, ImageFormat::Png)?;
            crate::sys::cli_file_CL_TYPE_PNG
        }
    };
    Ok((cursor.into_inner(), image_type))
}

#[export_name = "pdf_render_to_image"]
pub unsafe extern "C" fn _pdf_render_to_image(
    file_bytes: *const u8,
    file_size: usize,
    config: *const PdfImageFuzzyHashConfig,
    rendered_image_out: *mut RenderedPdfImage,
    err: *mut *mut crate::ffi_util::FFIError,
) -> bool {
    if rendered_image_out.is_null() {
        return crate::ffi_error!(
            err = err,
            crate::ffi_util::Error::NullParameter("rendered_image_out".to_string())
        );
    }
    if file_bytes.is_null() {
        return crate::ffi_error!(
            err = err,
            crate::ffi_util::Error::NullParameter("file_bytes".to_string())
        );
    }

    let buffer = std::slice::from_raw_parts(file_bytes, file_size);
    let render_result = render_to_image(buffer, config.as_ref());

    match render_result {
        Ok((image_data, image_type)) => {
            let len = image_data.len();
            let boxed = image_data.into_boxed_slice();
            let ptr = Box::into_raw(boxed) as *mut u8;

            *rendered_image_out = RenderedPdfImage {
                image_data: ptr,
                image_len: len,
                image_type,
            };
            true
        }
        Err(e) => {
            *err = Box::into_raw(Box::new(e.into()));
            false
        }
    }
}

#[export_name = "pdf_rendered_image_free"]
pub unsafe extern "C" fn _pdf_rendered_image_free(image_data: *mut u8, image_len: usize) {
    if image_data.is_null() {
        return;
    }

    let slice_ptr = std::ptr::slice_from_raw_parts_mut(image_data, image_len);
    drop(Box::from_raw(slice_ptr));
}
