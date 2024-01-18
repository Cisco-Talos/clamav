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

#[derive(thiserror::Error, Debug)]
pub enum PdfRenderError {
    #[error("PDF Rendering error : {0}")]
    PDFRenderError(#[from] PdfiumError),

    #[error("PDF Rendering error : empty document")]
    PDFRenderEmpty,
}

pub fn render(data: &[u8]) -> Result<DynamicImage, PdfRenderError> {
    let pdfium = Pdfium::new(Pdfium::bind_to_system_library()?); 
    let document = pdfium.load_pdf_from_byte_slice(data, None)?;

    if document.pages().is_empty()
    {
        return Err(PdfRenderError::PDFRenderEmpty);
    }

    let render_config = PdfRenderConfig::new()
        .set_target_width(2000)
        .set_maximum_height(2000);

    let image = document.pages().first()?.render_with_config(&render_config)?.as_image(); 
    Ok(image)
}
