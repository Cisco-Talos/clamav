use super::*;

impl BcjFilter {
    pub(crate) fn new_ia64(start_pos: usize, encoder: bool) -> Self {
        Self {
            is_encoder: encoder,
            pos: start_pos,
            prev_mask: 0,
            filter: Self::ia64_code,
        }
    }

    fn ia64_code(&mut self, buf: &mut [u8]) -> usize {
        const BRANCH_TABLE: [u32; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4,
            4, 0, 0,
        ];

        if buf.len() < 16 {
            return 0;
        }

        let end = buf.len() - 16;
        let mut i = 0;

        while i <= end {
            let instr_template = (buf[i] & 0x1F) as usize;
            let mask = BRANCH_TABLE[instr_template];

            for slot in 0..3 {
                let bit_pos = 5 + slot * 41;

                if ((mask >> slot) & 1) == 0 {
                    continue;
                }

                let byte_pos = bit_pos >> 3;
                let bit_res = bit_pos & 7;

                // Extract 6 bytes starting from byte_pos.
                let mut instr: u64 = 0;
                for j in 0..6 {
                    if i + byte_pos + j < buf.len() {
                        instr |= (buf[i + byte_pos + j] as u64) << (8 * j);
                    }
                }

                let instr_norm = instr >> bit_res;

                // Check if this is a branch instruction.
                if ((instr_norm >> 37) & 0x0F) != 0x05 || ((instr_norm >> 9) & 0x07) != 0x00 {
                    continue;
                }

                // Extract the source address.
                let mut src = ((instr_norm >> 13) & 0x0FFFFF) as i32;
                src |= (((instr_norm >> 36) & 1) as i32) << 20;
                src <<= 4;

                // Calculate destination address.
                let dest = if self.is_encoder {
                    src.wrapping_add((self.pos as i32).wrapping_add(i as i32))
                } else {
                    src.wrapping_sub((self.pos as i32).wrapping_add(i as i32))
                };

                let dest = (dest as u32) >> 4;

                // Update the instruction.
                let mut instr_norm = instr_norm;
                instr_norm &= !(0x8FFFFF_u64 << 13);
                instr_norm |= ((dest & 0x0FFFFF) as u64) << 13;
                instr_norm |= ((dest & 0x100000) as u64) << (36 - 20);

                let mut instr = instr & ((1_u64 << bit_res) - 1);
                instr |= instr_norm << bit_res;

                // Write the modified instruction back.
                for j in 0..6 {
                    if i + byte_pos + j < buf.len() {
                        buf[i + byte_pos + j] = (instr >> (8 * j)) as u8;
                    }
                }
            }

            i += 16;
        }

        self.pos = self.pos.wrapping_add(i);

        i
    }
}
