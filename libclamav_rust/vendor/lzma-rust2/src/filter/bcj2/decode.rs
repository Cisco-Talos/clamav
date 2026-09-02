use super::*;
use crate::ByteReader;

#[derive(Debug)]
pub(crate) struct Bcj2Decoder {
    pub(crate) bufs: [usize; BCJ2_NUM_STREAMS],
    pub(crate) lims: [usize; BCJ2_NUM_STREAMS],
    dest: usize,

    // BCJ2_STREAM_MAIN has more priority than BCJ2_STATE_ORIG.
    pub(crate) state: usize,

    ip: u32,
    temp: [u8; 4],
    range: u32,
    pub(crate) code: u32,
    probs: [u16; 2 + 256],
}

impl Bcj2Decoder {
    pub(crate) fn new() -> Self {
        Self {
            bufs: Default::default(),
            lims: Default::default(),
            dest: Default::default(),
            state: BCJ2_DEC_STATE_OK,
            ip: Default::default(),
            temp: Default::default(),
            range: Default::default(),
            code: Default::default(),
            probs: [BIT_MODEL_TOTAL >> 1; 2 + 256],
        }
    }

    #[inline(always)]
    pub(crate) fn dest(&self) -> usize {
        self.dest
    }

    #[inline(always)]
    pub(crate) fn set_dest(&mut self, dest: usize) {
        self.dest = dest;
    }

    pub(crate) fn decode(&mut self, src_bufs: &mut [u8], dest_buf: &mut [u8]) -> bool {
        let dest_lim = dest_buf.len();
        if self.range <= 5 {
            self.state = BCJ2_DEC_STATE_OK;
            while self.range != 5 {
                if self.range == 1 && self.code != 0 {
                    return false;
                }
                if self.bufs[BCJ2_STREAM_RC] == self.lims[BCJ2_STREAM_RC] {
                    self.state = BCJ2_STREAM_RC;
                    return true;
                }

                self.code = (self.code << 8) | src_bufs[self.bufs[BCJ2_STREAM_RC]] as u32;
                self.bufs[BCJ2_STREAM_RC] = self.bufs[BCJ2_STREAM_RC].wrapping_add(1);
                self.range += 1;
            }

            if self.code == 0xFFFFFFFF {
                return false;
            }

            self.range = 0xFFFFFFFF;
        } else if self.state >= BCJ2_DEC_STATE_ORIG_0 {
            while self.state <= BCJ2_DEC_STATE_ORIG_3 {
                let dest = self.dest;
                if dest == dest_lim {
                    return true;
                }
                dest_buf[dest] = self.temp[self.state - BCJ2_DEC_STATE_ORIG_0];
                self.state += 1;
                self.dest = dest + 1;
            }
        }

        loop {
            if bcj2_is_32bit_stream(self.state) {
                self.state = BCJ2_DEC_STATE_OK;
            } else {
                if self.range < K_TOP_VALUE {
                    if self.bufs[BCJ2_STREAM_RC] == self.lims[BCJ2_STREAM_RC] {
                        self.state = BCJ2_STREAM_RC;
                        return true;
                    }
                    self.range <<= 8;
                    self.code = (self.code << 8) | src_bufs[self.bufs[BCJ2_STREAM_RC]] as u32;
                    self.bufs[BCJ2_STREAM_RC] = self.bufs[BCJ2_STREAM_RC].wrapping_add(1);
                }

                {
                    let mut src = self.bufs[BCJ2_STREAM_MAIN];
                    let mut num = self.lims[BCJ2_STREAM_MAIN] - src;

                    if num == 0 {
                        self.state = BCJ2_STREAM_MAIN;
                        return true;
                    }

                    let mut dest = self.dest;
                    if num > (dest_lim - dest) {
                        num = dest_lim - dest;
                        if num == 0 {
                            self.state = BCJ2_DEC_STATE_ORIG;
                            return true;
                        }
                    }

                    let src_lim = src + num;

                    if self.temp[3] == 0x0F && (src_bufs[src] & 0xF0) == 0x80 {
                        dest_buf[dest] = src_bufs[src];
                    } else {
                        loop {
                            let b = src_bufs[src];
                            dest_buf[dest] = b;
                            if b != 0x0F {
                                if (b & 0xFE) == 0xE8 {
                                    break;
                                }
                                dest += 1;
                                src += 1;
                                if src != src_lim {
                                    continue;
                                }
                                break;
                            }
                            dest += 1;
                            src += 1;
                            if src == src_lim {
                                break;
                            }
                            if (src_bufs[src] & 0xF0) != 0x80 {
                                continue;
                            }
                            dest_buf[dest] = src_bufs[src];
                            break;
                        }
                    }

                    num = src - self.bufs[BCJ2_STREAM_MAIN];

                    if src == src_lim {
                        self.temp[3] = src_bufs[src - 1];
                        self.bufs[BCJ2_STREAM_MAIN] = src;
                        self.ip += num as u32;
                        self.dest += num;
                        self.state = if self.bufs[BCJ2_STREAM_MAIN] == self.lims[BCJ2_STREAM_MAIN] {
                            BCJ2_STREAM_MAIN
                        } else {
                            BCJ2_DEC_STATE_ORIG
                        };
                        return true;
                    }

                    {
                        let b = src_bufs[src];
                        let prev = if num == 0 {
                            self.temp[3]
                        } else {
                            src_bufs[src - 1]
                        };

                        self.temp[3] = b;
                        self.bufs[BCJ2_STREAM_MAIN] = src + 1;
                        num += 1;
                        self.ip += num as u32;
                        self.dest += num;

                        let prob = &mut self.probs[if b == 0xE8 {
                            2 + prev as usize
                        } else if b == 0xE9 {
                            1
                        } else {
                            0
                        }];

                        //   _IF_BIT_0
                        let ttt = *prob;
                        let bound = (self.range >> NUM_MODEL_BITS) * ttt as u32;
                        if self.code < bound {
                            // _UPDATE_0
                            self.range = bound;
                            *prob = (ttt + ((BIT_MODEL_TOTAL - ttt) >> NUM_MOVE_BITS)) as _;
                            continue;
                        }
                        //   _UPDATE_1
                        self.range -= bound;
                        self.code -= bound;
                        *prob = ttt - (ttt >> NUM_MOVE_BITS);
                    }
                }
            }

            {
                let cj = if self.temp[3] == 0xE8 {
                    BCJ2_STREAM_CALL
                } else {
                    BCJ2_STREAM_JUMP
                };
                let cur = self.bufs[cj];

                if cur == self.lims[cj] {
                    self.state = cj;
                    break;
                }

                let mut val = if let Ok(v) = (&mut &src_bufs[cur..]).read_u32_be() {
                    v
                } else {
                    return false;
                };
                self.bufs[cj] = cur + 4;

                self.ip += 4;
                val = val.wrapping_sub(self.ip);
                let dest = self.dest;
                let rem = dest_lim - dest;

                if rem < 4 {
                    self.temp[0] = val as u8;
                    if rem > 0 {
                        dest_buf[dest] = val as u8;
                    }
                    val >>= 8;
                    self.temp[1] = val as u8;
                    if rem > 1 {
                        dest_buf[dest + 1] = val as u8;
                    }
                    val >>= 8;
                    self.temp[2] = val as u8;
                    if rem > 2 {
                        dest_buf[dest + 2] = val as u8;
                    }
                    val >>= 8;
                    self.temp[3] = val as u8;
                    self.dest = dest + rem;
                    self.state = BCJ2_DEC_STATE_ORIG_0 + rem;
                    break;
                }
                dest_buf[dest..dest + 4].copy_from_slice(&val.to_le_bytes());
                //   SetUi32(dest, val);
                self.temp[3] = (val >> 24) as u8;
                self.dest = dest + 4;
            }
        }

        if self.range < K_TOP_VALUE && self.bufs[BCJ2_STREAM_RC] != self.lims[BCJ2_STREAM_RC] {
            self.range <<= 8;
            self.code = (self.code << 8) | src_bufs[self.bufs[BCJ2_STREAM_RC]] as u32;
            self.bufs[BCJ2_STREAM_RC] = self.bufs[BCJ2_STREAM_RC].wrapping_add(1);
        }

        true
    }
}
