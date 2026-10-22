// Grayscale specialization of image 0.25.8's imageops/sample.rs Lanczos resize.
// Preserve the sampling bounds, floating-point operation order, and rounding:
// existing fuzzy-image signatures depend on the exact resulting pixels.
//
// Adapted from the image crate (https://github.com/image-rs/image), MIT license:
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do
// so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use image::{GrayImage, ImageBuffer, Luma};

const HASH_SIDE: u32 = 32;

fn sinc(value: f32) -> f32 {
    let angle = value * std::f32::consts::PI;
    if value == 0.0 {
        1.0
    } else {
        angle.sin() / angle
    }
}

// Return the first contributing input pixel and its normalized filter weights.
fn weights(size: u32, output: u32, values: &mut Vec<f32>) -> usize {
    let ratio = size as f32 / HASH_SIDE as f32;
    let scale = if ratio < 1.0 { 1.0 } else { ratio };
    let support = 3.0 * scale;
    let center = (output as f32 + 0.5) * ratio;
    let left = ((center - support).floor() as i64).clamp(0, i64::from(size) - 1);
    let right = ((center + support).ceil() as i64).clamp(left + 1, i64::from(size));
    let center = center - 0.5;

    values.clear();
    let mut sum = 0.0;
    for input in left..right {
        let distance = (input as f32 - center) / scale;
        let weight = if distance.abs() < 3.0 {
            sinc(distance) * sinc(distance / 3.0)
        } else {
            0.0
        };
        values.push(weight);
        sum += weight;
    }
    for weight in values.iter_mut() {
        *weight /= sum;
    }
    left as usize
}

pub(super) fn lanczos3_32(image: &GrayImage) -> GrayImage {
    let (width, height) = image.dimensions();
    if width == 0 || height == 0 {
        return GrayImage::new(HASH_SIDE, HASH_SIDE);
    }
    if (width, height) == (HASH_SIDE, HASH_SIDE) {
        return image.clone();
    }

    // Keep just the luminance channel, rather than the generic resizer's RGBA
    // intermediate. ImageBuffer checks the allocation's dimension arithmetic.
    let mut vertical: ImageBuffer<Luma<f32>, Vec<f32>> = ImageBuffer::new(width, HASH_SIDE);
    let mut filter = Vec::new();
    let stride = width as usize;
    for (y, row) in vertical.as_mut().chunks_exact_mut(stride).enumerate() {
        let first = weights(height, y as u32, &mut filter);
        let source = &image.as_raw()[first * stride..];
        // Visit contiguous rows for locality and SIMD across independent output
        // pixels. Each pixel still accumulates source rows in the original order.
        for (source_row, &weight) in source.chunks_exact(stride).zip(&filter) {
            for (dest, &pixel) in row.iter_mut().zip(source_row) {
                *dest += f32::from(pixel) * weight;
            }
        }
    }

    let mut out = GrayImage::new(HASH_SIDE, HASH_SIDE);
    for x in 0..HASH_SIDE {
        let first = weights(width, x, &mut filter);
        for (source_row, dest_row) in vertical
            .as_raw()
            .chunks_exact(stride)
            .zip(out.as_mut().chunks_exact_mut(HASH_SIDE as usize))
        {
            let mut value = 0.0;
            for (&pixel, &weight) in source_row[first..].iter().zip(&filter) {
                value += pixel * weight;
            }
            dest_row[x as usize] = value.clamp(0.0, 255.0).round() as u8;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::imageops::{resize, FilterType::Lanczos3};

    #[test]
    fn matches_generic_lanczos_pixels() {
        // Empty and unit dimensions, the no-resize case, anisotropic inputs,
        // up/downsampling boundaries, and larger images. Compare every pixel,
        // which is stricter than comparing only the final 64-bit hash.
        let mut sizes = vec![
            (0, 0),
            (0, 19),
            (23, 0),
            (1024, 3),
            (3, 1024),
            (641, 479),
            (1920, 1080),
            (65536, 1),
            (1, 65536),
        ];
        for width in [1, 2, 7, 31, 32, 33, 63, 64, 65, 127] {
            for height in [1, 2, 7, 31, 32, 33, 63, 64, 65, 127] {
                sizes.push((width, height));
            }
        }
        let mut random = 0x12345678u32;
        for _ in 0..64 {
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            let width = 1 + random % 1024;
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            sizes.push((width, 1 + random % 1024));
        }
        for (width, height) in sizes {
            for pattern in 0..5 {
                let input = GrayImage::from_fn(width, height, |x, y| {
                    random ^= random << 13;
                    random ^= random >> 17;
                    random ^= random << 5;
                    Luma([match pattern {
                        0 => 0,
                        1 => 255,
                        2 => {
                            if (x + y) % 2 == 0 {
                                0
                            } else {
                                255
                            }
                        }
                        3 => ((x * 17 + y * 29) % 256) as u8,
                        _ => random as u8,
                    }])
                });
                let expected = resize(&input, HASH_SIDE, HASH_SIDE, Lanczos3);
                assert_eq!(
                    lanczos3_32(&input).as_raw(),
                    expected.as_raw(),
                    "{width}x{height}, pattern {pattern}"
                );
            }
        }
    }
}
