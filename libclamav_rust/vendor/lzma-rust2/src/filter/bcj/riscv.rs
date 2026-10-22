use super::*;

impl BcjFilter {
    pub(crate) fn new_riscv(start_pos: usize, encoder: bool) -> Self {
        Self {
            is_encoder: encoder,
            pos: start_pos,
            prev_mask: 0,
            filter: Self::riscv_code,
        }
    }

    fn riscv_code(&mut self, buf: &mut [u8]) -> usize {
        let len = buf.len();
        if len < 8 {
            return 0;
        }

        let end = len - 8;
        let mut i = 0;

        while i <= end {
            let inst = buf[i] as u32;

            if inst == 0xEF {
                // JAL
                let b1 = buf[i + 1] as u32;

                // Only filter rd=x1(ra) and rd=x5(t0).
                if (b1 & 0x0D) != 0 {
                    i += 2;
                    continue;
                }

                let b2 = buf[i + 2] as u32;
                let b3 = buf[i + 3] as u32;
                let pc = (self.pos + i) as i32;

                if self.is_encoder {
                    // Encoder: Decode address bits from the instruction format.
                    let addr = ((b1 & 0xF0) << 8)
                        | ((b2 & 0x0F) << 16)
                        | ((b2 & 0x10) << 7)
                        | ((b2 & 0xE0) >> 4)
                        | ((b3 & 0x7F) << 4)
                        | ((b3 & 0x80) << 13);

                    let addr = (addr as i32).wrapping_add(pc);

                    buf[i + 1] = ((b1 & 0x0F) | ((addr as u32 >> 13) & 0xF0)) as u8;
                    buf[i + 2] = (addr >> 9) as u8;
                    buf[i + 3] = (addr >> 1) as u8;
                } else {
                    // Decoder: Encode address bits back to instruction format.
                    let addr = ((b1 & 0xF0) << 13) | (b2 << 9) | (b3 << 1);
                    let addr = (addr as i32).wrapping_sub(pc);

                    buf[i + 1] = ((b1 & 0x0F) | ((addr as u32 >> 8) & 0xF0)) as u8;
                    buf[i + 2] =
                        (((addr >> 16) & 0x0F) | ((addr >> 7) & 0x10) | ((addr << 4) & 0xE0)) as u8;
                    buf[i + 3] = (((addr >> 4) & 0x7F) | ((addr >> 13) & 0x80)) as u8;
                }

                i += 4;
            } else if (inst & 0x7F) == 0x17 {
                // AUIPC
                let mut inst_full = inst
                    | ((buf[i + 1] as u32) << 8)
                    | ((buf[i + 2] as u32) << 16)
                    | ((buf[i + 3] as u32) << 24);

                if (inst_full & 0xE80) != 0 {
                    // AUIPC's rd doesn't equal x0 or x2.

                    let inst2 =
                        u32::from_le_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);

                    if (((inst_full << 8) ^ inst2) & 0xF8003) != 3 {
                        i += 6;
                        continue;
                    }

                    if self.is_encoder {
                        let addr =
                            ((inst_full & 0xFFFFF000) as i32).wrapping_add((inst2 as i32) >> 20);
                        let addr = addr.wrapping_add((self.pos + i) as i32);

                        // Construct the first 32 bits.
                        inst_full = 0x17 | (2 << 7) | (inst2 << 12);

                        buf[i] = inst_full as u8;
                        buf[i + 1] = (inst_full >> 8) as u8;
                        buf[i + 2] = (inst_full >> 16) as u8;
                        buf[i + 3] = (inst_full >> 24) as u8;

                        // Store address in big endian.
                        buf[i + 4] = (addr >> 24) as u8;
                        buf[i + 5] = (addr >> 16) as u8;
                        buf[i + 6] = (addr >> 8) as u8;
                        buf[i + 7] = addr as u8;
                    } else {
                        let addr =
                            ((inst_full & 0xFFFFF000) as i32).wrapping_add((inst2 >> 20) as i32);

                        inst_full = 0x17 | (2 << 7) | (inst2 << 12);
                        let inst2_new = addr;

                        buf[i] = inst_full as u8;
                        buf[i + 1] = (inst_full >> 8) as u8;
                        buf[i + 2] = (inst_full >> 16) as u8;
                        buf[i + 3] = (inst_full >> 24) as u8;

                        buf[i + 4] = inst2_new as u8;
                        buf[i + 5] = (inst2_new >> 8) as u8;
                        buf[i + 6] = (inst2_new >> 16) as u8;
                        buf[i + 7] = (inst2_new >> 24) as u8;
                    }
                } else {
                    // AUIPC's rd equals x0 or x2.
                    let fake_rs1 = inst_full >> 27;

                    if ((inst_full.wrapping_sub(0x3100)) & 0x3F80) >= (fake_rs1 & 0x1D) {
                        i += 4;
                        continue;
                    }

                    if self.is_encoder {
                        let fake_addr =
                            u32::from_le_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);

                        let fake_inst2 = (inst_full >> 12) | (fake_addr << 20);

                        inst_full = 0x17 | (fake_rs1 << 7) | (fake_addr & 0xFFFFF000);

                        buf[i] = inst_full as u8;
                        buf[i + 1] = (inst_full >> 8) as u8;
                        buf[i + 2] = (inst_full >> 16) as u8;
                        buf[i + 3] = (inst_full >> 24) as u8;

                        buf[i + 4] = fake_inst2 as u8;
                        buf[i + 5] = (fake_inst2 >> 8) as u8;
                        buf[i + 6] = (fake_inst2 >> 16) as u8;
                        buf[i + 7] = (fake_inst2 >> 24) as u8;
                    } else {
                        let addr =
                            i32::from_be_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);

                        let addr = addr.wrapping_sub((self.pos + i) as i32);

                        let inst2_rs1 = inst_full >> 27;
                        let inst2 = (inst_full >> 12) | ((addr as u32) << 20);

                        inst_full = 0x17
                            | (inst2_rs1 << 7)
                            | ((addr.wrapping_add(0x800) as u32) & 0xFFFFF000);

                        buf[i] = inst_full as u8;
                        buf[i + 1] = (inst_full >> 8) as u8;
                        buf[i + 2] = (inst_full >> 16) as u8;
                        buf[i + 3] = (inst_full >> 24) as u8;

                        buf[i + 4] = inst2 as u8;
                        buf[i + 5] = (inst2 >> 8) as u8;
                        buf[i + 6] = (inst2 >> 16) as u8;
                        buf[i + 7] = (inst2 >> 24) as u8;
                    }
                }

                i += 8;
            } else {
                i += 2;
            }
        }

        self.pos = self.pos.wrapping_add(i);

        i
    }
}
