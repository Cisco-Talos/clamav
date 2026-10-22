use super::{
    MATCH_LEN_MAX, MATCH_LEN_MIN, REPS,
    encoder::LzmaEncoderTrait,
    lz::{LzEncoder, MfType},
};

#[derive(Default)]
pub(crate) struct FastEncoderMode {}

impl FastEncoderMode {
    pub(crate) const EXTRA_SIZE_BEFORE: u32 = 1;
    pub(crate) const EXTRA_SIZE_AFTER: u32 = MATCH_LEN_MAX as u32 - 1;

    pub(crate) fn get_memory_usage(dict_size: u32, extra_size_before: u32, mf: MfType) -> u32 {
        LzEncoder::get_memory_usage(
            dict_size,
            extra_size_before.max(Self::EXTRA_SIZE_BEFORE),
            Self::EXTRA_SIZE_AFTER,
            MATCH_LEN_MAX as u32,
            mf,
        )
    }
}

fn change_pair(small_dist: u32, big_dist: u32) -> bool {
    small_dist < (big_dist >> 7)
}

impl LzmaEncoderTrait for FastEncoderMode {
    fn get_next_symbol(&mut self, encoder: &mut super::encoder::LzmaEncoder) -> u32 {
        if encoder.data.read_ahead == -1 {
            encoder.find_matches();
        }

        encoder.data.back = -1;
        let avail = encoder.lz.data.get_avail().min(MATCH_LEN_MAX as i32);
        if avail < MATCH_LEN_MIN as i32 {
            return 1;
        }
        let mut best_rep_len = 0;
        let mut best_rep_index = 0;
        for rep in 0..REPS {
            let len = encoder
                .lz
                .data
                .get_match_len(encoder.coder.reps[rep], avail);
            if len < MATCH_LEN_MIN {
                continue;
            }
            if len >= encoder.data.nice_len {
                encoder.data.back = rep as i32;
                encoder.skip(len - 1);
                return len as u32;
            }
            if len > best_rep_len {
                best_rep_index = rep;
                best_rep_len = len;
            }
        }

        let mut main_len = 0;
        let mut main_dist = 0;
        let matches = encoder.lz.matches();
        if matches.count > 0 {
            main_len = matches.len[matches.count as usize - 1];
            main_dist = matches.dist[matches.count as usize - 1];

            if main_len >= encoder.data.nice_len as u32 {
                encoder.data.back = (main_dist + REPS as i32) as _;
                encoder.skip((main_len - 1) as _);
                return main_len;
            }

            while matches.count > 1 && main_len == matches.len[matches.count as usize - 2] + 1 {
                if !change_pair(
                    matches.dist[matches.count as usize - 2] as u32,
                    main_dist as u32,
                ) {
                    break;
                }
                matches.count -= 1;
                main_len = matches.len[matches.count as usize - 1];
                main_dist = matches.dist[matches.count as usize - 1];
            }

            if main_len == MATCH_LEN_MIN as u32 && main_dist >= 0x80 {
                main_len = 1;
            }
        }

        if best_rep_len >= MATCH_LEN_MIN
            && (best_rep_len + 1 >= main_len as usize
                || (best_rep_len + 2 >= main_len as usize && main_dist >= (1 << 9))
                || (best_rep_len + 3 >= main_len as usize && main_dist >= (1 << 15)))
        {
            encoder.data.back = best_rep_index as _;
            encoder.skip(best_rep_len - 1);
            return best_rep_len as _;
        }

        if main_len < MATCH_LEN_MIN as _ || avail <= MATCH_LEN_MIN as _ {
            return 1;
        }
        // Get the next match. Test if it is better than the current match.
        // If so, encode the current byte as a literal.
        encoder.find_matches();
        let matches = encoder.lz.matches();
        if matches.count > 0 {
            let new_len = matches.len[matches.count as usize - 1];
            let new_dist = matches.dist[matches.count as usize - 1];

            if (new_len >= main_len && new_dist < main_dist)
                || (new_len == main_len + 1 && !change_pair(main_dist as _, new_dist as _))
                || new_len > main_len + 1
                || (new_len + 1 >= main_len
                    && main_len > MATCH_LEN_MIN as u32
                    && change_pair(new_dist as _, main_dist as _))
            {
                return 1;
            }
        }

        let limit = (main_len - 1).max(MATCH_LEN_MIN as _);
        for rep in 0..REPS {
            if encoder
                .lz
                .get_match_len(encoder.coder.reps[rep], limit as i32)
                == limit as usize
            {
                return 1;
            }
        }

        encoder.data.back = (main_dist + REPS as i32) as _;
        encoder.skip((main_len - 2) as _);
        main_len
    }
}
