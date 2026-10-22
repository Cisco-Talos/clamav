use alloc::vec::Vec;

use crate::{Read, error_invalid_data, error_other, error_out_of_memory};

#[derive(Default)]
pub(crate) struct LzDecoder {
    buf: Vec<u8>,
    buf_size: usize,
    start: usize,
    pos: usize,
    full: usize,
    limit: usize,
    pending_len: usize,
    pending_dist: usize,
    pending_preset: Option<Vec<u8>>,
    allocated: bool,
}

impl LzDecoder {
    pub(crate) fn new(dict_size: usize, preset_dict: Option<&[u8]>) -> Self {
        let mut pos = 0;
        let mut full = 0;
        let mut start = 0;
        let mut pending_preset = None;
        if let Some(preset) = preset_dict {
            pos = preset.len().min(dict_size);
            full = pos;
            start = pos;
            let ps = preset.len() - pos;
            pending_preset = Some(preset[ps..].to_vec());
        }
        Self {
            buf: Vec::new(),
            buf_size: dict_size,
            pos,
            full,
            start,
            pending_preset,
            allocated: false,
            ..Default::default()
        }
    }

    /// Allocates the dictionary window on first use, fallibly, so a malicious
    /// `dict_size` returns an error instead of aborting the process.
    pub(crate) fn ensure_capacity(&mut self) -> crate::Result<()> {
        if self.allocated {
            return Ok(());
        }
        self.buf
            .try_reserve_exact(self.buf_size)
            .map_err(|_| error_out_of_memory("dictionary allocation too large"))?;
        self.buf.resize(self.buf_size, 0);
        if let Some(preset) = self.pending_preset.take() {
            self.buf[..preset.len()].copy_from_slice(&preset);
        }
        self.allocated = true;
        Ok(())
    }

    pub(crate) fn reset(&mut self) {
        self.start = 0;
        self.pos = 0;
        self.full = 0;
        self.limit = 0;
        self.buf[self.buf_size - 1] = 0;
    }

    pub(crate) fn set_limit(&mut self, out_max: usize) {
        self.limit = (out_max + self.pos).min(self.buf_size);
    }

    pub(crate) fn has_space(&self) -> bool {
        self.pos < self.limit
    }

    pub(crate) fn has_pending(&self) -> bool {
        self.pending_len > 0
    }

    pub(crate) fn get_pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn get_byte(&self, dist: usize) -> u8 {
        let offset = if dist >= self.pos {
            self.buf_size
                .saturating_add(self.pos)
                .saturating_sub(dist)
                .saturating_sub(1)
        } else {
            self.pos.saturating_sub(dist).saturating_sub(1)
        };

        self.buf.get(offset).copied().unwrap_or(0)
    }

    pub(crate) fn put_byte(&mut self, b: u8) {
        self.buf[self.pos] = b;
        self.pos += 1;
        if self.full < self.pos {
            self.full = self.pos;
        }
    }

    pub(crate) fn repeat(&mut self, dist: usize, len: usize) -> crate::Result<()> {
        if dist >= self.full {
            return Err(error_other("dist overflow"));
        }
        let mut left = usize::min(self.limit - self.pos, len);
        self.pending_len = len - left;
        self.pending_dist = dist;

        let back = if self.pos < dist + 1 {
            // The distance wraps around to the end of the cyclic dictionary
            // buffer. We cannot get here if the dictionary isn't full.
            debug_assert_eq!(self.full, self.buf_size);
            let mut back = self.buf_size + self.pos - dist - 1;

            let copy_size = usize::min(self.buf_size - back, left);
            self.buf.copy_within(back..back + copy_size, self.pos);
            self.pos += copy_size;
            back = 0;
            left -= copy_size;

            if left == 0 {
                return Ok(());
            }

            back
        } else {
            self.pos - dist - 1
        };

        debug_assert!(back < self.pos);
        debug_assert!(left > 0);

        if dist >= left {
            // No overlap possible. We can copy directly.
            let (src_part, dst_part) = self.buf.split_at_mut(self.pos);
            dst_part[..left].copy_from_slice(&src_part[back..back + left]);
            self.pos += left;
        } else {
            loop {
                let copy_size = left.min(self.pos - back);
                self.buf.copy_within(back..back + copy_size, self.pos);
                self.pos += copy_size;
                left -= copy_size;
                if left == 0 {
                    break;
                }
            }
        }

        if self.full < self.pos {
            self.full = self.pos;
        }
        Ok(())
    }

    pub(crate) fn repeat_pending(&mut self) -> crate::Result<()> {
        if self.pending_len > 0 {
            self.repeat(self.pending_dist, self.pending_len)?;
        }
        Ok(())
    }

    pub(crate) fn copy_uncompressed<R: Read>(
        &mut self,
        mut in_data: R,
        len: usize,
    ) -> crate::Result<()> {
        let copy_size = (self.buf_size - self.pos).min(len);
        let buf = &mut self.buf[self.pos..(self.pos + copy_size)];
        in_data.read_exact(buf)?;
        self.pos += copy_size;
        if self.full < self.pos {
            self.full = self.pos;
        }
        Ok(())
    }

    pub(crate) fn copy_uncompressed_from_slice(&mut self, data: &[u8]) -> crate::Result<()> {
        let copy_size = (self.buf_size - self.pos).min(data.len());
        self.buf[self.pos..self.pos + copy_size].copy_from_slice(&data[..copy_size]);
        self.pos += copy_size;
        if self.full < self.pos {
            self.full = self.pos;
        }
        Ok(())
    }

    pub(crate) fn available_space(&self) -> usize {
        self.buf_size - self.pos
    }

    pub(crate) fn has_output(&self) -> bool {
        self.pos > self.start
    }

    pub(crate) fn flush_partial(&mut self, out: &mut [u8]) -> usize {
        let available = self.pos.saturating_sub(self.start);
        let copy_size = available.min(out.len());
        if copy_size > 0 {
            out[..copy_size].copy_from_slice(&self.buf[self.start..self.start + copy_size]);
            self.start += copy_size;
        }
        if self.start == self.pos && self.pos == self.buf_size {
            self.pos = 0;
            self.start = 0;
        }
        copy_size
    }

    pub(crate) fn flush(&mut self, out: &mut [u8], out_off: usize) -> crate::Result<usize> {
        let copy_size = self.pos.saturating_sub(self.start);

        if self.pos == self.buf_size {
            self.pos = 0;
        }

        let src = self
            .buf
            .get(self.start..(self.start + copy_size))
            .ok_or(error_invalid_data("invalid source range"))?;

        let dst = out
            .get_mut(out_off..(out_off + copy_size))
            .ok_or(error_invalid_data("invalid destination range"))?;

        dst.copy_from_slice(src);

        self.start = self.pos;

        Ok(copy_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_capacity_rejects_impossible_size() {
        let mut lz = LzDecoder::new(usize::MAX, None);
        assert!(lz.ensure_capacity().is_err());
    }
}
