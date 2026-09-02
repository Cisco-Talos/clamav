use alloc::{vec, vec::Vec};

use super::{
    MATCH_LEN_MAX, MATCH_LEN_MIN, REPS,
    encoder::{LzmaEncoder, LzmaEncoderTrait},
    lz::{LzEncoder, MfType},
    state::State,
};

pub(crate) struct NormalEncoderMode {
    opts: Vec<Optimum>,
    opt_cur: usize,
    opt_end: usize,
}

impl NormalEncoderMode {
    const OPTS: u32 = 4096;

    pub(crate) const EXTRA_SIZE_BEFORE: u32 = Self::OPTS;

    pub(crate) const EXTRA_SIZE_AFTER: u32 = Self::OPTS;

    pub(crate) fn get_memory_usage(dict_size: u32, extra_size_before: u32, mf: MfType) -> u32 {
        LzEncoder::get_memory_usage(
            dict_size,
            extra_size_before.max(Self::EXTRA_SIZE_BEFORE),
            Self::EXTRA_SIZE_AFTER,
            MATCH_LEN_MAX as u32,
            mf,
        ) + Self::OPTS * 64 / 1024
    }

    pub(crate) fn new() -> Self {
        Self {
            opts: vec![Optimum::default(); Self::OPTS as usize],
            opt_cur: 0,
            opt_end: 0,
        }
    }

    fn convert_opts(&mut self, encoder: &mut LzmaEncoder) -> usize {
        self.opt_end = self.opt_cur;

        let mut opt_prev = self.opts[self.opt_cur].opt_prev;

        loop {
            let opt_index = self.opt_cur;

            if self.opts[opt_index].prev1_is_literal {
                self.opts[opt_prev].opt_prev = self.opt_cur;
                self.opts[opt_prev].back_prev = -1;
                self.opt_cur = opt_prev;
                opt_prev -= 1;

                if self.opts[opt_index].has_prev2 {
                    self.opts[opt_prev].opt_prev = opt_prev + 1;
                    self.opts[opt_prev].back_prev = self.opts[opt_index].back_prev2;
                    self.opt_cur = opt_prev;
                    opt_prev = self.opts[opt_index].opt_prev2;
                }
            }

            let temp = self.opts[opt_prev].opt_prev;
            self.opts[opt_prev].opt_prev = self.opt_cur;
            self.opt_cur = opt_prev;
            opt_prev = temp;
            if self.opt_cur == 0 {
                break;
            }
        }

        self.opt_cur = self.opts[0].opt_prev;
        encoder.data.back = self.opts[self.opt_cur].back_prev;
        self.opt_cur
    }

    fn update_opt_state_and_reps(&mut self) {
        let mut opt_prev = self.opts[self.opt_cur].opt_prev;
        debug_assert!(opt_prev < self.opt_cur);

        if self.opts[self.opt_cur].prev1_is_literal {
            opt_prev -= 1;

            if self.opts[self.opt_cur].has_prev2 {
                let state = self.opts[self.opts[self.opt_cur].opt_prev2].state;
                self.opts[self.opt_cur].state.set(state);
                if self.opts[self.opt_cur].back_prev2 < REPS as i32 {
                    self.opts[self.opt_cur].state.update_long_rep();
                } else {
                    self.opts[self.opt_cur].state.update_match();
                }
            } else {
                let state = self.opts[opt_prev].state;
                self.opts[self.opt_cur].state.set(state);
            }

            self.opts[self.opt_cur].state.update_literal();
        } else {
            let state = self.opts[opt_prev].state;
            self.opts[self.opt_cur].state.set(state);
        }

        if opt_prev == self.opt_cur - 1 {
            // Must be either a short rep or a literal.
            debug_assert!(
                self.opts[self.opt_cur].back_prev == 0 || self.opts[self.opt_cur].back_prev == -1
            );

            if self.opts[self.opt_cur].back_prev == 0 {
                self.opts[self.opt_cur].state.update_short_rep();
            } else {
                self.opts[self.opt_cur].state.update_literal();
            }

            self.opts[self.opt_cur].reps = self.opts[opt_prev].reps;
        } else {
            let back;
            if self.opts[self.opt_cur].prev1_is_literal && self.opts[self.opt_cur].has_prev2 {
                opt_prev = self.opts[self.opt_cur].opt_prev2;
                back = self.opts[self.opt_cur].back_prev2;
                self.opts[self.opt_cur].state.update_long_rep();
            } else {
                back = self.opts[self.opt_cur].back_prev;
                if back < REPS as i32 {
                    self.opts[self.opt_cur].state.update_long_rep();
                } else {
                    self.opts[self.opt_cur].state.update_match();
                }
            }

            if back < REPS as i32 {
                self.opts[self.opt_cur].reps[0] = self.opts[opt_prev].reps[back as usize];

                for rep in 1..=back as usize {
                    self.opts[self.opt_cur].reps[rep] = self.opts[opt_prev].reps[rep - 1];
                }
                for rep in (back as usize + 1)..REPS {
                    self.opts[self.opt_cur].reps[rep] = self.opts[opt_prev].reps[rep];
                }
            } else {
                self.opts[self.opt_cur].reps[0] = back - REPS as i32;
                let tmp: [i32; REPS] = self.opts[opt_prev].reps;
                self.opts[self.opt_cur].reps[1..].copy_from_slice(&tmp[..3]);
            }
        }
    }

    fn calc1_byte_prices(
        &mut self,
        encoder: &mut LzmaEncoder,
        pos: u32,
        pos_state: u32,
        avail: i32,
        any_rep_price: u32,
    ) {
        // This will be set to true if using a literal or a short rep.
        let mut next_is_byte = false;
        let cur_byte = encoder.lz.get_byte_backward(0);
        let match_byte = encoder
            .lz
            .get_byte_backward(self.opts[self.opt_cur].reps[0] + 1);

        // Try a literal.
        let literal_price = self.opts[self.opt_cur].price
            + encoder.literal_encoder.get_price(
                encoder,
                cur_byte as _,
                match_byte as _,
                encoder.lz.get_byte_backward(1) as _,
                pos,
                &self.opts[self.opt_cur].state,
            );
        if literal_price < self.opts[self.opt_cur + 1].price {
            self.opts[self.opt_cur + 1].set1(literal_price, self.opt_cur, -1);
            next_is_byte = true;
        }
        let mut next_state = State::new();
        // Try a short rep.
        if match_byte == cur_byte
            && (self.opts[self.opt_cur + 1].opt_prev == self.opt_cur
                || self.opts[self.opt_cur + 1].back_prev != 0)
        {
            let short_rep_price = encoder.get_short_rep_price(
                any_rep_price,
                &self.opts[self.opt_cur].state,
                pos_state,
            );
            if short_rep_price <= self.opts[self.opt_cur + 1].price {
                self.opts[self.opt_cur + 1].set1(short_rep_price, self.opt_cur, 0);
                next_is_byte = true;
            }
        }

        // If neither a literal nor a short rep was the cheapest choice,
        // try literal + long rep0.
        if !next_is_byte && match_byte != cur_byte && avail > MATCH_LEN_MIN as i32 {
            let len_limit = (encoder.data.nice_len as i32).min(avail - 1);
            let len = encoder
                .lz
                .get_match_len2(1, self.opts[self.opt_cur].reps[0], len_limit);

            if len >= MATCH_LEN_MIN as u32 {
                next_state.set(self.opts[self.opt_cur].state);
                next_state.update_literal();
                let next_pos_state = (pos + 1) & encoder.coder.pos_mask;
                let price = literal_price
                    + encoder.get_long_rep_and_len_price(0, len, &next_state, next_pos_state);

                let i = self.opt_cur + 1 + len as usize;
                while self.opt_end < i {
                    self.opt_end += 1;
                    self.opts[self.opt_end].reset();
                }
                if price < self.opts[i].price {
                    self.opts[i].set2(price, self.opt_cur, 0);
                }
            }
        }
    }

    fn calc_long_rep_prices(
        &mut self,
        encoder: &mut LzmaEncoder,
        pos: u32,
        pos_state: u32,
        avail: i32,
        any_rep_price: u32,
    ) -> usize {
        let mut start_len = MATCH_LEN_MIN;
        let len_limit = avail.min(encoder.data.nice_len as i32);
        let mut next_state = State::new();

        for rep in 0..REPS {
            let len = encoder.lz.get_match_len_fast_reject::<MATCH_LEN_MIN>(
                self.opts[self.opt_cur].reps[rep],
                len_limit,
            );

            if len < MATCH_LEN_MIN {
                continue;
            }

            while self.opt_end < self.opt_cur + len {
                self.opt_end += 1;
                self.opts[self.opt_end].reset();
            }

            let long_rep_price = encoder.get_long_rep_price(
                any_rep_price,
                rep as u32,
                &self.opts[self.opt_cur].state,
                pos_state,
            );

            // i=len;i>=MATCH_LEN_MIN;--i
            for i in (MATCH_LEN_MIN..=len).rev() {
                let price =
                    long_rep_price + encoder.rep_len_encoder.get_price(i, pos_state as usize);
                if price < self.opts[self.opt_cur + i].price {
                    self.opts[self.opt_cur + i].set1(price, self.opt_cur, rep as i32);
                }
            }

            if rep == 0 {
                start_len = len + 1;
            }
            let len2_limit = i32::min(encoder.data.nice_len as i32, avail - len as i32 - 1);
            // debug_assert!(
            //     len2_limit >= 0,
            //     "len2_limit>=0, len2_limit={}, avail={}, len={}",
            //     len2_limit,
            //     avail,
            //     len
            // );
            let len2 = encoder.lz.get_match_len2(
                len as i32 + 1,
                self.opts[self.opt_cur].reps[rep],
                len2_limit,
            );

            if len2 >= MATCH_LEN_MIN as u32 {
                // Rep
                let mut price =
                    long_rep_price + encoder.rep_len_encoder.get_price(len, pos_state as _);
                next_state.set(self.opts[self.opt_cur].state);
                next_state.update_long_rep();

                // Literal
                let cur_byte = encoder.lz.get_byte(len as _, 0);
                let match_byte = encoder.lz.get_byte_backward(0); // lz.getByte(len, len)
                let prev_byte = encoder.lz.get_byte(len as _, 1);
                price += encoder.literal_encoder.get_price(
                    encoder,
                    cur_byte as u32,
                    match_byte as u32,
                    prev_byte as u32,
                    pos + len as u32,
                    &next_state,
                );
                next_state.update_literal();

                // Rep0
                let next_pos_state = (pos + len as u32 + 1) & encoder.coder.pos_mask;
                price += encoder.get_long_rep_and_len_price(0, len2, &next_state, next_pos_state);

                let i = self.opt_cur + len + 1 + len2 as usize;
                while self.opt_end < i {
                    self.opt_end += 1;
                    self.opts[self.opt_end].reset();
                }
                if price < self.opts[i].price {
                    self.opts[i].set3(price, self.opt_cur, rep as _, len, 0);
                }
            }
        }

        start_len
    }

    fn calc_normal_match_prices(
        &mut self,
        encoder: &mut LzmaEncoder,
        pos: u32,
        pos_state: u32,
        avail: i32,
        any_match_price: u32,
        start_len: u32,
    ) {
        // If the longest match is so long that it would not fit into
        // the opts array, shorten the matches.
        {
            let matches = encoder.lz.matches();
            if matches.len[matches.count as usize - 1] as i32 > avail {
                matches.count = 0;
                while (matches.len[matches.count as usize] as i32) < avail {
                    matches.count += 1;
                }
                let count = matches.count as usize;
                matches.len[count] = avail as u32;
                matches.count += 1;
            }

            if matches.len[matches.count as usize - 1] < start_len {
                return;
            }
            while self.opt_end < self.opt_cur + matches.len[matches.count as usize - 1] as usize {
                self.opt_end += 1;
                self.opts[self.opt_end].reset();
            }
        }
        let normal_match_price =
            encoder.get_normal_match_price(any_match_price, &self.opts[self.opt_cur].state);

        let mut _match = 0;
        while start_len > encoder.lz.matches().len[_match] {
            _match += 1;
        }
        let mut len = start_len;
        let mut next_state = State::new();
        loop {
            let dist = encoder.lz.matches().dist[_match];

            // Calculate the price of a match of len bytes from the nearest
            // possible distance.
            let match_and_len_price =
                encoder.get_match_and_len_price(normal_match_price, dist as _, len, pos_state);
            if match_and_len_price < self.opts[self.opt_cur + len as usize].price {
                self.opts[self.opt_cur + len as usize].set1(
                    match_and_len_price,
                    self.opt_cur,
                    dist + REPS as i32,
                );
            }
            if len != encoder.lz.matches().len[_match] {
                len += 1;
                continue;
            }

            // Try match + literal + rep0. First get the length of the rep0.
            let len2_limit = i32::min(encoder.data.nice_len as i32, avail - len as i32 - 1);
            let len2 = encoder.lz.get_match_len2(len as i32 + 1, dist, len2_limit);

            if len2 >= MATCH_LEN_MIN as _ {
                next_state.set(self.opts[self.opt_cur].state);
                next_state.update_match();

                // Literal
                let cur_byte = encoder.lz.get_byte(len as _, 0) as u32;
                let match_byte = encoder.lz.get_byte_backward(0) as u32; // lz.getByte(len, len)
                let prev_byte = encoder.lz.get_byte(len as _, 1) as u32;
                let mut price = match_and_len_price
                    + encoder.literal_encoder.get_price(
                        encoder,
                        cur_byte,
                        match_byte,
                        prev_byte,
                        pos + len,
                        &next_state,
                    );
                next_state.update_literal();

                // Rep0
                let next_pos_state = (pos + len + 1) & encoder.coder.pos_mask;
                price += encoder.get_long_rep_and_len_price(0, len2, &next_state, next_pos_state);

                let i = self.opt_cur + len as usize + 1 + len2 as usize;
                while self.opt_end < i {
                    self.opt_end += 1;
                    self.opts[self.opt_end].reset();
                }
                if price < self.opts[i].price {
                    self.opts[i].set3(price, self.opt_cur, dist + REPS as i32, len as usize, 0);
                }
            }

            _match += 1;
            if _match == encoder.lz.matches().count as usize {
                break;
            }
            len += 1;
        }
    }
}

impl LzmaEncoderTrait for NormalEncoderMode {
    fn get_next_symbol(&mut self, encoder: &mut LzmaEncoder) -> u32 {
        // If there are pending symbols from an earlier call to this
        // function, return those symbols first.
        let pos = encoder.lz.get_pos();
        debug_assert!(pos >= 0);
        if self.opt_cur < self.opt_end {
            let len = self.opts[self.opt_cur].opt_prev as i32 - self.opt_cur as i32;
            self.opt_cur = self.opts[self.opt_cur].opt_prev;
            encoder.data.back = self.opts[self.opt_cur].back_prev;
            debug_assert!(len >= 0);
            return len as u32;
        }

        debug_assert_eq!(self.opt_cur, self.opt_end);
        self.opt_cur = 0;
        self.opt_end = 0;
        encoder.data.back = -1;
        if encoder.data.read_ahead == -1 {
            encoder.find_matches();
        }

        // Get the number of bytes available in the dictionary, but
        // not more than the maximum match length. If there aren't
        // enough bytes remaining to encode a match at all, return
        // immediately to encode this byte as a literal.
        let mut avail = i32::min(encoder.lz.get_avail(), MATCH_LEN_MAX as i32);
        if avail < MATCH_LEN_MIN as i32 {
            return 1;
        }
        // Get the lengths of repeated matches.
        let mut rep_best = 0;
        let mut rep_lens = [0; REPS];
        for rep in 0..REPS {
            rep_lens[rep] = encoder.lz.get_match_len(encoder.coder.reps[rep], avail) as i32;

            if rep_lens[rep] < MATCH_LEN_MIN as i32 {
                rep_lens[rep] = 0;
                continue;
            }

            if rep_lens[rep] > rep_lens[rep_best] {
                rep_best = rep;
            }
        }

        // Return if the best repeated match is at least niceLen bytes long.
        if rep_lens[rep_best] >= encoder.data.nice_len as i32 {
            encoder.data.back = rep_best as _;
            encoder.skip((rep_lens[rep_best] - 1) as usize);
            return rep_lens[rep_best] as _;
        }

        // Initialize mainLen and mainDist to the longest match found
        // by the match finder.
        let mut main_len = 0;
        let main_dist;
        let matches = encoder.lz.matches();
        if matches.count > 0 {
            main_len = matches.len[matches.count as usize - 1] as usize;
            main_dist = matches.dist[matches.count as usize - 1];

            // Return if it is at least niceLen bytes long.
            if main_len >= encoder.data.nice_len {
                encoder.data.back = main_dist + REPS as i32;
                encoder.skip(main_len - 1);
                return main_len as u32;
            }
        }

        let cur_byte = encoder.lz.get_byte_backward(0) as u32;
        let match_byte = encoder.lz.get_byte_backward(encoder.coder.reps[0] + 1) as u32;

        // If the match finder found no matches and this byte cannot be
        // encoded as a repeated match (short or long), we must be return
        // to have the byte encoded as a literal.
        if main_len < MATCH_LEN_MIN
            && cur_byte != match_byte
            && rep_lens[rep_best] < MATCH_LEN_MIN as i32
        {
            return 1;
        }

        let mut pos = encoder.lz.get_pos() as u32;
        let mut pos_state = pos & encoder.coder.pos_mask;

        // Calculate the price of encoding the current byte as a literal.
        {
            let prev_byte = encoder.lz.get_byte_backward(1) as u32;
            let state = encoder.coder.state;
            let literal_price = encoder
                .literal_encoder
                .get_price(encoder, cur_byte, match_byte, prev_byte, pos, &state);
            self.opts[1].set1(literal_price, 0, -1);
        }

        let mut any_match_price = encoder.get_any_match_price(&encoder.coder.state, pos_state);
        let mut any_rep_price = encoder.get_any_rep_price(any_match_price, &encoder.coder.state);

        // If it is possible to encode this byte as a short rep, see if
        // it is cheaper than encoding it as a literal.
        if match_byte == cur_byte {
            let short_rep_price =
                encoder.get_short_rep_price(any_rep_price, &encoder.coder.state, pos_state);
            if short_rep_price < self.opts[1].price {
                self.opts[1].set1(short_rep_price, 0, 0);
            }
        }

        // Return if there is neither normal nor long repeated match. Use
        // a short match instead of a literal if it is possible and cheaper.
        self.opt_end = usize::max(main_len, rep_lens[rep_best] as usize);
        if self.opt_end < MATCH_LEN_MIN {
            debug_assert_eq!(self.opt_end, 0);
            encoder.data.back = self.opts[1].back_prev;
            return 1;
        }

        // Update the lookup tables for distances and lengths before using
        // those price calculation functions. (The price function above
        // don't need these tables.)
        encoder.update_prices();

        // Initialize the state and reps of this position in opts[].
        // updateOptStateAndReps() will need these to get the new
        // state and reps for the next byte.
        self.opts[0].state.set(encoder.coder.state);
        self.opts[0].reps = encoder.coder.reps;

        // Initialize the prices for latter opts that will be used below.
        for i in (MATCH_LEN_MIN..=self.opt_end).rev() {
            self.opts[i].reset();
        }

        // Calculate the prices of repeated matches of all lengths.
        for (rep, &rep_len) in rep_lens.iter().enumerate() {
            if rep_len < MATCH_LEN_MIN as i32 {
                continue;
            }
            let long_rep_price = encoder.get_long_rep_price(
                any_rep_price,
                rep as _,
                &encoder.coder.state,
                pos_state,
            );
            let mut rep_len = rep_len as usize;
            loop {
                let price = long_rep_price
                    + encoder
                        .rep_len_encoder
                        .get_price(rep_len as _, pos_state as _);
                if price < self.opts[rep_len].price {
                    self.opts[rep_len].set1(price, 0, rep as _);
                }
                rep_len -= 1;
                if rep_len < MATCH_LEN_MIN {
                    break;
                }
            }
        }

        // Calculate the prices of normal matches that are longer than rep0.
        {
            let mut len = i32::max(rep_lens[0] + 1, MATCH_LEN_MIN as i32);
            if len <= main_len as i32 {
                let normal_match_price =
                    encoder.get_normal_match_price(any_match_price, &encoder.coder.state);

                // Set i to the index of the shortest match that is
                // at least len bytes long.
                let mut i = 0;
                while len > encoder.lz.matches().len[i] as i32 {
                    i += 1;
                }

                loop {
                    let dist = encoder.lz.matches().dist[i];
                    let price = encoder.get_match_and_len_price(
                        normal_match_price,
                        dist as _,
                        len as _,
                        pos_state,
                    );
                    if price < self.opts[len as usize].price {
                        self.opts[len as usize].set1(price, 0, dist + REPS as i32);
                    }
                    if len == encoder.lz.matches().len[i] as i32 {
                        i += 1;
                        if i == encoder.lz.matches().count as usize {
                            break;
                        }
                    }
                    len += 1;
                }
            }
        }

        avail = i32::min(encoder.lz.get_avail(), Self::OPTS as i32 - 1);

        // Get matches for later bytes and optimize the use of LZMA symbols
        // by calculating the prices and picking the cheapest symbol
        // combinations.
        while {
            self.opt_cur += 1;
            self.opt_cur < self.opt_end
        } {
            encoder.find_matches();
            let matches = encoder.lz.matches();
            if matches.count > 0
                && matches.len[matches.count as usize - 1] >= encoder.data.nice_len as u32
            {
                break;
            }

            avail -= 1;
            pos += 1;
            pos_state = pos & encoder.coder.pos_mask;

            self.update_opt_state_and_reps();
            any_match_price = self.opts[self.opt_cur].price
                + encoder.get_any_match_price(&self.opts[self.opt_cur].state, pos_state);
            any_rep_price =
                encoder.get_any_rep_price(any_match_price, &self.opts[self.opt_cur].state);

            self.calc1_byte_prices(encoder, pos, pos_state, avail as _, any_rep_price);

            if avail >= MATCH_LEN_MIN as i32 {
                let start_len =
                    self.calc_long_rep_prices(encoder, pos, pos_state, avail as _, any_rep_price);
                if encoder.lz.matches().count > 0 {
                    self.calc_normal_match_prices(
                        encoder,
                        pos,
                        pos_state,
                        avail as _,
                        any_match_price,
                        start_len as _,
                    );
                }
            }
        }

        self.convert_opts(encoder) as _
    }

    fn reset(&mut self) {
        self.opt_cur = 0;
        self.opt_end = 0;
    }
}

#[derive(Debug, Default, Clone)]
struct Optimum {
    state: State,
    reps: [i32; REPS],

    price: u32,
    opt_prev: usize,
    back_prev: i32,
    prev1_is_literal: bool,

    has_prev2: bool,
    opt_prev2: usize,
    back_prev2: i32,
}

impl Optimum {
    const INFINITY_PRICE: u32 = 1 << 30;

    fn reset(&mut self) {
        self.price = Self::INFINITY_PRICE;
    }

    fn set1(&mut self, new_price: u32, opt_cur: usize, back: i32) {
        self.price = new_price;
        self.opt_prev = opt_cur;
        self.back_prev = back;
        self.prev1_is_literal = false;
    }

    fn set2(&mut self, new_price: u32, opt_cur: usize, back: i32) {
        self.price = new_price;
        self.opt_prev = opt_cur + 1;
        self.back_prev = back;
        self.prev1_is_literal = true;
        self.has_prev2 = false;
    }

    fn set3(&mut self, new_price: u32, opt_cur: usize, back2: i32, len2: usize, back: i32) {
        self.price = new_price;
        self.opt_prev = opt_cur + len2 + 1;
        self.back_prev = back;
        self.prev1_is_literal = true;
        self.has_prev2 = true;
        self.opt_prev2 = opt_cur;
        self.back_prev2 = back2;
    }
}
