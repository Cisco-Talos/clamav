use alloc::{vec, vec::Vec};

use super::{
    ALIGN_BITS, DIST_MODEL_END, DIST_MODEL_START, LOW_SYMBOLS, LengthCoder, LiteralCoder,
    LiteralSubCoder, LzmaCoder, MATCH_LEN_MIN, MID_SYMBOLS, coder_get_dict_size, lz::LzDecoder,
    range_dec::RangeDecoder,
};
use crate::range_dec::RangeReader;

pub(crate) struct LzmaDecoder {
    coder: LzmaCoder,
    literal_decoder: LiteralDecoder,
    match_len_decoder: LengthCoder,
    rep_len_decoder: LengthCoder,
}

impl LzmaDecoder {
    pub(crate) fn new(lc: u32, lp: u32, pb: u32) -> Self {
        let mut literal_decoder = LiteralDecoder::new(lc, lp);
        literal_decoder.reset();
        let match_len_decoder = {
            let mut l = LengthCoder::new();
            l.reset();
            l
        };
        let rep_len_decoder = {
            let mut l = LengthCoder::new();
            l.reset();
            l
        };
        Self {
            coder: LzmaCoder::new(pb as _),
            literal_decoder,
            match_len_decoder,
            rep_len_decoder,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.coder.reset();
        self.literal_decoder.reset();
        self.match_len_decoder.reset();
        self.rep_len_decoder.reset();
    }

    pub(crate) fn end_marker_detected(&self) -> bool {
        self.coder.reps[0] == -1
    }

    pub(crate) fn decode<R: RangeReader>(
        &mut self,
        lz: &mut LzDecoder,
        rc: &mut RangeDecoder<R>,
    ) -> crate::Result<()> {
        lz.repeat_pending()?;
        while lz.has_space() && rc.can_start_symbol() {
            let pos_state = lz.get_pos() as u32 & self.coder.pos_mask;
            let i = self.coder.state.get() as usize;
            let probs = &mut self.coder.is_match[i];
            let bit = rc.decode_bit(&mut probs[pos_state as usize]);
            if bit == 0 {
                self.literal_decoder.decode(&mut self.coder, lz, rc)?;
            } else {
                let index = self.coder.state.get() as usize;
                let len = if rc.decode_bit(&mut self.coder.is_rep[index]) == 0 {
                    self.decode_match(pos_state, rc)
                } else {
                    self.decode_rep_match(pos_state, rc)
                };
                lz.repeat(self.coder.reps[0] as _, len as _)?;
            }
        }
        // Normalise only if we stopped because the output is full. If we
        // stopped because the input ran out, `rc` has to stay as it is, so that
        // the next call can pick up where this one left off. A reader that
        // never runs out of input, like `RangeDecoderBuffer`, always takes this
        // branch, just like before.
        if !lz.has_space() && rc.can_normalize() {
            rc.normalize();
        }
        Ok(())
    }

    fn decode_match<R: RangeReader>(&mut self, pos_state: u32, rc: &mut RangeDecoder<R>) -> u32 {
        self.coder.state.update_match();
        self.coder.reps[3] = self.coder.reps[2];
        self.coder.reps[2] = self.coder.reps[1];
        self.coder.reps[1] = self.coder.reps[0];

        let len = self.match_len_decoder.decode(pos_state as _, rc);
        let dist_slot =
            rc.decode_bit_tree(&mut self.coder.dist_slots[coder_get_dict_size(len as _)]);

        if dist_slot < DIST_MODEL_START as i32 {
            self.coder.reps[0] = dist_slot as _;
        } else {
            let limit = (dist_slot >> 1) - 1;
            self.coder.reps[0] = (2 | (dist_slot & 1)) << limit;
            if dist_slot < DIST_MODEL_END as i32 {
                let probs = self
                    .coder
                    .get_dist_special((dist_slot - DIST_MODEL_START as i32) as usize);
                self.coder.reps[0] |= rc.decode_reverse_bit_tree(probs);
            } else {
                let r0 = rc.decode_direct_bits(limit as u32 - ALIGN_BITS as u32) << ALIGN_BITS;
                self.coder.reps[0] |= r0;
                self.coder.reps[0] |= rc.decode_reverse_bit_tree(&mut self.coder.dist_align);
            }
        }

        len as _
    }

    fn decode_rep_match<R: RangeReader>(
        &mut self,
        pos_state: u32,
        rc: &mut RangeDecoder<R>,
    ) -> u32 {
        let index = self.coder.state.get() as usize;
        if rc.decode_bit(&mut self.coder.is_rep0[index]) == 0 {
            let index: usize = self.coder.state.get() as usize;
            if rc.decode_bit(&mut self.coder.is_rep0_long[index][pos_state as usize]) == 0 {
                self.coder.state.update_short_rep();
                return 1;
            }
        } else {
            let tmp;
            let s = self.coder.state.get() as usize;
            if rc.decode_bit(&mut self.coder.is_rep1[s]) == 0 {
                tmp = self.coder.reps[1];
            } else {
                if rc.decode_bit(&mut self.coder.is_rep2[s]) == 0 {
                    tmp = self.coder.reps[2];
                } else {
                    tmp = self.coder.reps[3];
                    self.coder.reps[3] = self.coder.reps[2];
                }
                self.coder.reps[2] = self.coder.reps[1];
            }
            self.coder.reps[1] = self.coder.reps[0];
            self.coder.reps[0] = tmp;
        }

        self.coder.state.update_long_rep();
        self.rep_len_decoder.decode(pos_state as _, rc) as u32
    }
}

pub(crate) struct LiteralDecoder {
    coder: LiteralCoder,
    sub_decoders: Vec<LiteralSubDecoder>,
}

impl LiteralDecoder {
    fn new(lc: u32, lp: u32) -> Self {
        let coder = LiteralCoder::new(lc, lp);
        let sub_decoders = vec![LiteralSubDecoder::new(); (1 << (lc + lp)) as _];

        Self {
            coder,
            sub_decoders,
        }
    }

    fn reset(&mut self) {
        for ele in self.sub_decoders.iter_mut() {
            ele.coder.reset()
        }
    }

    fn decode<R: RangeReader>(
        &mut self,
        coder: &mut LzmaCoder,
        lz: &mut LzDecoder,
        rc: &mut RangeDecoder<R>,
    ) -> crate::Result<()> {
        let i = self
            .coder
            .get_sub_coder_index(lz.get_byte(0) as _, lz.get_pos() as _);
        let d = &mut self.sub_decoders[i as usize];
        d.decode(coder, lz, rc)
    }
}

#[derive(Clone)]
struct LiteralSubDecoder {
    coder: LiteralSubCoder,
}

impl LiteralSubDecoder {
    fn new() -> Self {
        Self {
            coder: LiteralSubCoder::new(),
        }
    }

    pub(crate) fn decode<R: RangeReader>(
        &mut self,
        coder: &mut LzmaCoder,
        lz: &mut LzDecoder,
        rc: &mut RangeDecoder<R>,
    ) -> crate::Result<()> {
        let mut symbol: u32 = 1;
        let liter = coder.state.is_literal();
        if liter {
            loop {
                let b = rc.decode_bit(&mut self.coder.probs[symbol as usize]) as u32;
                symbol = (symbol << 1) | b;
                if symbol >= 0x100 {
                    break;
                }
            }
        } else {
            let r = coder.reps[0];
            let mut match_byte = lz.get_byte(r as usize) as u32;
            let mut offset = 0x100;
            let mut match_bit;
            let mut bit;

            loop {
                match_byte <<= 1;
                match_bit = match_byte & offset;
                bit = rc.decode_bit(&mut self.coder.probs[(offset + match_bit + symbol) as usize])
                    as u32;
                symbol = (symbol << 1) | bit;
                offset &= (0u32.wrapping_sub(bit)) ^ !match_bit;
                if symbol >= 0x100 {
                    break;
                }
            }
        }
        lz.put_byte(symbol as u8);
        coder.state.update_literal();
        Ok(())
    }
}

impl LengthCoder {
    fn decode<R: RangeReader>(&mut self, pos_state: usize, rc: &mut RangeDecoder<R>) -> i32 {
        if rc.decode_bit(&mut self.choice[0]) == 0 {
            return rc
                .decode_bit_tree(&mut self.low[pos_state])
                .wrapping_add(MATCH_LEN_MIN as _);
        }

        if rc.decode_bit(&mut self.choice[1]) == 0 {
            return rc
                .decode_bit_tree(&mut self.mid[pos_state])
                .wrapping_add(MATCH_LEN_MIN as _)
                .wrapping_add(LOW_SYMBOLS as _);
        }

        rc.decode_bit_tree(&mut self.high)
            .wrapping_add(MATCH_LEN_MIN as _)
            .wrapping_add(LOW_SYMBOLS as _)
            .wrapping_add(MID_SYMBOLS as _)
    }
}
