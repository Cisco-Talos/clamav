use super::*;

impl BcjFilter {
    pub(crate) fn new_power_pc(start_pos: usize, encoder: bool) -> Self {
        Self {
            is_encoder: encoder,
            pos: start_pos,
            prev_mask: 0,
            filter: Self::ppc_code,
        }
    }

    fn ppc_code(&mut self, buf: &mut [u8]) -> usize {
        if buf.len() < 4 {
            return 0;
        }
        let end = buf.len() - 4;
        let mut i = 0;
        while i <= end {
            let b3 = buf[i + 3] as i32;
            let b0 = buf[i] as i32;

            if (b0 & 0xFC) == 0x48 && (b3 & 0x03) == 0x01 {
                let b2 = buf[i + 2] as i32;
                let b1 = buf[i + 1] as i32;

                let src =
                    ((b0 & 0x03) << 24) | ((b1 & 0xFF) << 16) | ((b2 & 0xFF) << 8) | (b3 & 0xFC);

                let p = self.pos.wrapping_add(i) as i32;
                let dest = if self.is_encoder {
                    src.wrapping_add(p)
                } else {
                    src.wrapping_sub(p)
                };

                buf[i] = (0x48 | ((dest >> 24) & 0x03)) as u8;
                buf[i + 1] = (dest >> 16) as u8;
                buf[i + 2] = (dest >> 8) as u8;
                buf[i + 3] = ((b3 & 0x03) | dest) as u8;
            }
            i += 4;
        }

        self.pos = self.pos.wrapping_add(i);
        i
    }
}
