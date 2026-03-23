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

use image::DynamicImage;
use pdfium_render::prelude::*;
use std::{ffi::CStr, os::raw::c_char, path::Path};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PdfImageFuzzyHashConfig {
    pub render_mode: u32,
    pub dpi: u32,
    pub canvas_width: u32,
    pub canvas_height: u32,
    pub output_path: *const c_char,
}

pub const PDF_IMAGE_FUZZY_HASH_RENDER_MODE_DEFAULT: u32 = 0;
pub const PDF_IMAGE_FUZZY_HASH_RENDER_MODE_DPI: u32 = 1;
pub const PDF_IMAGE_FUZZY_HASH_RENDER_MODE_CANVAS: u32 = 2;

#[derive(thiserror::Error, Debug)]
pub enum PdfRenderError {
    #[error("PDF Rendering error : {0}")]
    PDFRenderError(#[from] PdfiumError),

    #[error("PDF Rendering error : {0}")]
    ImageSaveError(#[from] image::ImageError),

    #[error("PDF Rendering error : empty document")]
    PDFRenderEmpty,

    #[error("PDF Rendering error : invalid rendered image path")]
    InvalidOutputPath,
}

impl Default for PdfImageFuzzyHashConfig {
    fn default() -> Self {
        Self {
            render_mode: PDF_IMAGE_FUZZY_HASH_RENDER_MODE_CANVAS,
            dpi: 0,
            canvas_width: 2000,
            canvas_height: 2000,
            output_path: std::ptr::null(),
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

    if !config.output_path.is_null() {
        let output_path = unsafe { CStr::from_ptr(config.output_path) }
            .to_str()
            .map_err(|_| PdfRenderError::InvalidOutputPath)?;
        image.save_with_format(Path::new(output_path), image::ImageFormat::Png)?;
    }

    Ok(image)
}
