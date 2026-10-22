use super::*;

impl BcjFilter {
    pub(crate) fn new_sparc(start_pos: usize, encoder: bool) -> Self {
        Self {
            is_encoder: encoder,
            pos: start_pos,
            prev_mask: 0,
            filter: Self::sparc_code,
        }
    }

    fn sparc_code(&mut self, buf: &mut [u8]) -> usize {
        if buf.len() < 4 {
            return 0;
        }
        let end = buf.len() - 4;
        let mut i = 0;
        while i <= end {
            let b0 = buf[i] as i32;
            let b1 = buf[i + 1] as i32;

            if (b0 == 0x40 && (b1 & 0xC0) == 0x00) || (b0 == 0x7F && (b1 & 0xC0) == 0xC0) {
                let b2 = buf[i + 2] as i32;
                let b3 = buf[i + 3] as i32;

                let src =
                    ((b0 & 0xFF) << 24) | ((b1 & 0xFF) << 16) | ((b2 & 0xFF) << 8) | (b3 & 0xFF);
                let src = src << 2;
                let p = self.pos.wrapping_add(i) as i32;
                let dest = if self.is_encoder {
                    src.wrapping_add(p)
                } else {
                    src.wrapping_sub(p)
                };
                let dest = dest >> 2;
                let dest = (((0 - ((dest >> 22) & 1)) << 22) & 0x3FFFFFFF)
                    | (dest & 0x3FFFFF)
                    | 0x40000000;

                buf[i] = (dest >> 24) as u8;
                buf[i + 1] = (dest >> 16) as u8;
                buf[i + 2] = (dest >> 8) as u8;
                buf[i + 3] = dest as u8;
            }
            i += 4;
        }

        self.pos = self.pos.wrapping_add(i);
        i
    }
}
