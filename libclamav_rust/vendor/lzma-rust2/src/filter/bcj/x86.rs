use super::*;

const MASK_TO_ALLOWED_STATUS: &[bool] = &[true, true, true, false, true, false, false, false];

const MASK_TO_BIT_NUMBER: &[u8] = &[0, 1, 2, 2, 3, 3, 3, 3];

#[inline(always)]
const fn test_86_ms_byte(b: u8) -> bool {
    b == 0x00 || b == 0xFF
}

impl BcjFilter {
    pub(crate) fn new_x86(start_pos: usize, encoder: bool) -> Self {
        Self {
            is_encoder: encoder,
            pos: start_pos.wrapping_add(5),
            prev_mask: 0,
            filter: Self::x86_code,
        }
    }

    fn x86_code(&mut self, buf: &mut [u8]) -> usize {
        let len = buf.len();
        if len < 5 {
            return 0;
        }
        let end = len - 5;
        let mut prev_pos = -1;
        let mut prev_mask = self.prev_mask;
        let mut i = 0;
        while i <= end {
            let b = buf[i];
            if b != 0xE9 && b != 0xE8 {
                i += 1;
                continue;
            }
            prev_pos = i as isize - prev_pos;
            if (prev_pos & !3) != 0 {
                prev_mask = 0;
            } else {
                prev_mask = (prev_mask << (prev_pos - 1)) & 7;
                if prev_mask != 0
                    && (!MASK_TO_ALLOWED_STATUS[prev_mask as usize]
                        || test_86_ms_byte(
                            buf[i + 4 - MASK_TO_BIT_NUMBER[prev_mask as usize] as usize],
                        ))
                {
                    prev_pos = i as isize;
                    prev_mask = (prev_mask << 1) | 1;
                    i += 1;
                    continue;
                }
            }

            prev_pos = i as isize;
            if test_86_ms_byte(buf[i + 4]) {
                let mut src = buf[i + 1] as i32
                    | ((buf[i + 2] as i32) << 8)
                    | ((buf[i + 3] as i32) << 16)
                    | ((buf[i + 4] as i32) << 24);
                let mut dest: i32;
                loop {
                    if self.is_encoder {
                        dest = src.wrapping_add((self.pos.wrapping_add(i)) as i32);
                    } else {
                        dest = src.wrapping_sub((self.pos.wrapping_add(i)) as i32);
                    }

                    if prev_mask == 0 {
                        break;
                    }

                    let index = MASK_TO_BIT_NUMBER[prev_mask as usize] * 8;
                    if !test_86_ms_byte(((dest >> (24 - index)) & 0xFF) as u8) {
                        break;
                    }

                    src = dest ^ ((1 << (32 - index)) - 1);
                }

                buf[i + 1] = dest as u8;
                buf[i + 2] = (dest >> 8) as u8;
                buf[i + 3] = (dest >> 16) as u8;
                buf[i + 4] = (!(((dest >> 24) & 1) - 1)) as u8;
                i += 4;
            } else {
                prev_mask = (prev_mask << 1) | 1;
            }
            i += 1;
        }

        prev_pos = i as isize - prev_pos;
        prev_mask = if (prev_pos & !3) != 0 {
            0
        } else {
            prev_mask << (prev_pos - 1)
        };

        self.prev_mask = prev_mask;
        self.pos = self.pos.wrapping_add(i);
        i
    }
}
