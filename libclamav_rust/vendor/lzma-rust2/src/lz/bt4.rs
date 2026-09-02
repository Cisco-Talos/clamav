use alloc::{vec, vec::Vec};

use super::{LzEncoder, MatchFind, Matches, extend_match, hash234::Hash234};

/// Binary Tree with 4-byte matching
pub(crate) struct Bt4 {
    hash: Hash234,
    tree: Vec<i32>,
    depth_limit: i32,
    cyclic_size: i32,
    cyclic_pos: i32,
    lz_pos: i32,
}

const MAX_POS: i32 = 0x7FFFFFFF;

#[inline(always)]
fn sh_left(i: i32) -> i32 {
    ((i as u32) << 1) as i32
}

impl Bt4 {
    pub(crate) fn new(dict_size: u32, nice_len: u32, depth_limit: i32) -> Self {
        let cyclic_size = dict_size as i32 + 1;

        let tree = vec![0; cyclic_size as usize * 2];

        Self {
            hash: Hash234::new(dict_size),
            tree,
            depth_limit: if depth_limit > 0 {
                depth_limit
            } else {
                16 + nice_len as i32 / 2
            },
            cyclic_size,
            cyclic_pos: -1,
            lz_pos: cyclic_size,
        }
    }

    pub(crate) fn get_mem_usage(dict_size: u32) -> u32 {
        Hash234::get_mem_usage(dict_size) + dict_size / (1024 / 8) + 10
    }

    fn move_pos(&mut self, encoder: &mut super::LzEncoderData) -> i32 {
        let avail = encoder.move_pos(encoder.nice_len as _, 4);
        if avail != 0 {
            self.lz_pos += 1;
            if self.lz_pos == MAX_POS {
                let normalization_offset = MAX_POS - self.cyclic_size;
                self.hash.normalize(normalization_offset);
                LzEncoder::normalize(&mut self.tree, normalization_offset);
                self.lz_pos -= normalization_offset;
            }
            self.cyclic_pos += 1;
            if self.cyclic_pos == self.cyclic_size {
                self.cyclic_pos = 0;
            }
        }
        avail
    }

    fn skip(
        &mut self,
        encoder: &mut super::LzEncoderData,
        nice_len_limit: i32,
        mut current_match: i32,
    ) {
        let mut depth = self.depth_limit;

        let mut ptr0 = sh_left(self.cyclic_pos) + 1;
        let mut ptr1 = sh_left(self.cyclic_pos);
        let mut len0 = 0;
        let mut len1 = 0;

        loop {
            let delta = self.lz_pos - current_match;

            if depth == 0 || delta >= self.cyclic_size {
                self.tree[ptr0 as usize] = 0;
                self.tree[ptr1 as usize] = 0;
                return;
            }
            depth -= 1;

            let pair_selector = self.cyclic_size * ((delta > self.cyclic_pos) as i32);
            let pair = sh_left(self.cyclic_pos - delta + pair_selector);

            let mut len = len0.min(len1);

            if encoder.get_byte_by_pos(encoder.read_pos + len - delta)
                == encoder.get_byte_by_pos(encoder.read_pos + len)
            {
                // No need to look for longer matches than niceLenLimit
                // because we only are updating the tree, not returning
                // matches found to the caller.
                loop {
                    len += 1;
                    if len == nice_len_limit {
                        self.tree[ptr1 as usize] = self.tree[pair as usize];
                        self.tree[ptr0 as usize] = self.tree[pair as usize + 1];
                        return;
                    }
                    if encoder.get_byte(len as _, delta as _) != encoder.get_byte(len as _, 0) {
                        break;
                    }
                }
            }

            if encoder.get_byte(len as _, delta) < encoder.get_byte(len as _, 0) {
                self.tree[ptr1 as usize] = current_match;
                ptr1 = pair + 1;
                current_match = self.tree[ptr1 as usize];
                len1 = len;
            } else {
                self.tree[ptr0 as usize] = current_match;
                ptr0 = pair;
                current_match = self.tree[ptr0 as usize];
                len0 = len;
            }
        }
    }
}

impl MatchFind for Bt4 {
    fn find_matches(&mut self, encoder: &mut super::LzEncoderData, matches: &mut Matches) {
        matches.count = 0;

        let mut match_len_limit = encoder.match_len_max as i32;
        let mut nice_len_limit = encoder.nice_len as i32;
        let avail = self.move_pos(encoder);

        if avail < match_len_limit {
            if avail == 0 {
                return;
            }
            match_len_limit = avail;
            if nice_len_limit > avail {
                nice_len_limit = avail;
            }
        }

        self.hash.calc_hashes(encoder.read_buffer());
        let mut delta2 = self.lz_pos - self.hash.get_hash2_pos();
        let delta3 = self.lz_pos - self.hash.get_hash3_pos();
        let mut current_match = self.hash.get_hash4_pos();
        self.hash.update_tables(self.lz_pos);

        let mut len_best = 0;

        // See if the hash from the first two bytes found a match.
        // The hashing algorithm guarantees that if the first byte
        // matches, also the second byte does, so there's no need to
        // test the second byte.
        if delta2 < self.cyclic_size
            && encoder.get_byte_backward(delta2) == encoder.get_current_byte()
        {
            len_best = 2;
            matches.len[0] = 2;
            matches.dist[0] = delta2 - 1;
            matches.count = 1;
        }

        // See if the hash from the first three bytes found a match that
        // is different from the match possibly found by the two-byte hash.
        // Also, here the hashing algorithm guarantees that if the first byte
        // matches, also the next two bytes do.
        if delta2 != delta3
            && delta3 < self.cyclic_size
            && encoder.get_byte_backward(delta3) == encoder.get_current_byte()
        {
            len_best = 3;
            let count = matches.count as usize;
            matches.dist[count] = delta3 - 1;
            matches.count += 1;
            delta2 = delta3;
        }

        // If a match was found, see how long it is.
        if matches.count > 0 {
            len_best = extend_match(
                &encoder.buf,
                encoder.read_pos,
                len_best,
                delta2,
                match_len_limit,
            );

            let c = matches.count as usize - 1;
            matches.len[c] = len_best as u32;

            // Return if it is long enough (niceLen or reached the end of
            // the dictionary).
            if len_best >= nice_len_limit {
                self.skip(encoder, nice_len_limit, current_match);
                return;
            }
        }

        // Long enough match wasn't found so easily. Look for better matches
        // from the binary tree.
        if len_best < 3 {
            len_best = 3;
        }
        let mut depth = self.depth_limit;

        let mut ptr0 = sh_left(self.cyclic_pos) + 1;
        let mut ptr1 = sh_left(self.cyclic_pos);
        let mut len0 = 0;
        let mut len1 = 0;

        loop {
            let delta = self.lz_pos - current_match;

            // Return if the search depth limit has been reached or
            // if the distance of the potential match exceeds the
            // dictionary size.
            if depth == 0 || delta >= self.cyclic_size {
                self.tree[ptr0 as usize] = 0;
                self.tree[ptr1 as usize] = 0;
                return;
            }
            depth -= 1;

            let pair_selector = self.cyclic_size * ((delta > self.cyclic_pos) as i32);
            let pair = sh_left(self.cyclic_pos - delta + pair_selector);

            let mut len = len0.min(len1);

            len = extend_match(
                encoder.buf.as_slice(),
                encoder.read_pos,
                len,
                delta,
                match_len_limit,
            );

            if len > len_best {
                len_best = len;
                let count = matches.count as usize;
                matches.len[count] = len as _;
                let count = matches.count as usize;
                matches.dist[count] = delta - 1;
                matches.count += 1;

                if len >= nice_len_limit {
                    self.tree[ptr1 as usize] = self.tree[pair as usize];
                    self.tree[ptr0 as usize] = self.tree[pair as usize + 1];
                    return;
                }
            }

            if (encoder.get_byte(len, delta)) < (encoder.get_byte(len, 0)) {
                self.tree[ptr1 as usize] = current_match;
                ptr1 = pair + 1;
                current_match = self.tree[ptr1 as usize];
                len1 = len;
            } else {
                self.tree[ptr0 as usize] = current_match;
                ptr0 = pair;
                current_match = self.tree[ptr0 as usize];
                len0 = len;
            }
        }
    }

    fn skip(&mut self, encoder: &mut super::LzEncoderData, len: usize) {
        let mut len = len as i32;
        while {
            let n = len > 0;
            len -= 1;
            n
        } {
            let mut nice_len_limit = encoder.nice_len as i32;
            let avail = self.move_pos(encoder);

            if avail < nice_len_limit {
                if avail == 0 {
                    continue;
                }
                nice_len_limit = avail;
            }

            self.hash.calc_hashes(encoder.read_buffer());
            let current_match = self.hash.get_hash4_pos();
            self.hash.update_tables(self.lz_pos);

            self.skip(encoder, nice_len_limit, current_match);
        }
    }
}
