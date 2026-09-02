use alloc::{vec, vec::Vec};
use core::ops::Deref;

use super::{bt4::Bt4, extend_match, hc4::Hc4};
use crate::Write;

/// Align to a 64-byte cache line
const MOVE_BLOCK_ALIGN: i32 = 64;
const MOVE_BLOCK_ALIGN_MASK: i32 = !(MOVE_BLOCK_ALIGN - 1);

pub(crate) trait MatchFind {
    fn find_matches(&mut self, encoder: &mut LzEncoderData, matches: &mut Matches);
    fn skip(&mut self, encoder: &mut LzEncoderData, len: usize);
}

pub(crate) enum MatchFinders {
    Hc4(Hc4),
    Bt4(Bt4),
}

impl MatchFind for MatchFinders {
    fn find_matches(&mut self, encoder: &mut LzEncoderData, matches: &mut Matches) {
        match self {
            MatchFinders::Hc4(m) => m.find_matches(encoder, matches),
            MatchFinders::Bt4(m) => m.find_matches(encoder, matches),
        }
    }

    fn skip(&mut self, encoder: &mut LzEncoderData, len: usize) {
        match self {
            MatchFinders::Hc4(m) => m.skip(encoder, len),
            MatchFinders::Bt4(m) => m.skip(encoder, len),
        }
    }
}

/// Match finders to use when encoding.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfType {
    /// Hash chain for 4 bytes entries (lower quality but faster).
    #[default]
    Hc4,
    /// Binary tree for 4 byte entries (higher quality but slower).
    Bt4,
}

impl MfType {
    #[inline]
    fn get_memory_usage(self, dict_size: u32) -> u32 {
        match self {
            MfType::Hc4 => Hc4::get_mem_usage(dict_size),
            MfType::Bt4 => Bt4::get_mem_usage(dict_size),
        }
    }
}

pub(crate) struct LzEncoder {
    pub(crate) data: LzEncoderData,
    pub(crate) matches: Matches,
    pub(crate) match_finder: MatchFinders,
}

pub(crate) struct LzEncoderData {
    pub(crate) keep_size_before: u32,
    pub(crate) keep_size_after: u32,
    pub(crate) match_len_max: u32,
    pub(crate) nice_len: u32,
    pub(crate) buf: Vec<u8>,
    pub(crate) buf_size: usize,
    pub(crate) buf_limit_u16: usize,
    pub(crate) read_pos: i32,
    pub(crate) read_limit: i32,
    pub(crate) finishing: bool,
    pub(crate) write_pos: i32,
    pub(crate) pending_size: u32,
}

pub(crate) struct Matches {
    pub(crate) len: Vec<u32>,
    pub(crate) dist: Vec<i32>,
    pub(crate) count: u32,
}

impl Matches {
    pub(crate) fn new(count_max: usize) -> Self {
        Self {
            len: vec![0; count_max],
            dist: vec![0; count_max],
            count: 0,
        }
    }
}

impl LzEncoder {
    pub(crate) fn get_memory_usage(
        dict_size: u32,
        extra_size_before: u32,
        extra_size_after: u32,
        match_len_max: u32,
        mf: MfType,
    ) -> u32 {
        get_buf_size(
            dict_size,
            extra_size_before,
            extra_size_after,
            match_len_max,
        ) + mf.get_memory_usage(dict_size)
    }

    pub(crate) fn new_hc4(
        dict_size: u32,
        extra_size_before: u32,
        extra_size_after: u32,
        nice_len: u32,
        match_len_max: u32,
        depth_limit: i32,
    ) -> Self {
        Self::new(
            dict_size,
            extra_size_before,
            extra_size_after,
            nice_len,
            match_len_max,
            MatchFinders::Hc4(Hc4::new(dict_size, nice_len, depth_limit)),
        )
    }

    pub(crate) fn new_bt4(
        dict_size: u32,
        extra_size_before: u32,
        extra_size_after: u32,
        nice_len: u32,
        match_len_max: u32,
        depth_limit: i32,
    ) -> Self {
        Self::new(
            dict_size,
            extra_size_before,
            extra_size_after,
            nice_len,
            match_len_max,
            MatchFinders::Bt4(Bt4::new(dict_size, nice_len, depth_limit)),
        )
    }

    fn new(
        dict_size: u32,
        extra_size_before: u32,
        extra_size_after: u32,
        nice_len: u32,
        match_len_max: u32,
        match_finder: MatchFinders,
    ) -> Self {
        let buf_size = get_buf_size(
            dict_size,
            extra_size_before,
            extra_size_after,
            match_len_max,
        );
        let buf_size = buf_size as usize;
        let buf = vec![0; buf_size];
        let buf_limit_u16 = buf_size.checked_sub(size_of::<u16>()).unwrap();

        let keep_size_before = extra_size_before + dict_size;
        let keep_size_after = extra_size_after + match_len_max;

        Self {
            data: LzEncoderData {
                keep_size_before,
                keep_size_after,
                match_len_max,
                nice_len,
                buf,
                buf_size,
                buf_limit_u16,
                read_pos: -1,
                read_limit: -1,
                finishing: false,
                write_pos: 0,
                pending_size: 0,
            },
            matches: Matches::new(nice_len as usize - 1),
            match_finder,
        }
    }

    pub(crate) fn normalize(positions: &mut [i32], norm_offset: i32) {
        #[cfg(all(feature = "std", feature = "optimization", target_arch = "x86_64"))]
        {
            if std::arch::is_x86_feature_detected!("avx2") {
                // SAFETY: We've checked that the CPU supports AVX2.
                return unsafe { normalize_avx2(positions, norm_offset) };
            }
            if std::arch::is_x86_feature_detected!("sse4.1") {
                // SAFETY: We've checked that the CPU supports SSE4.1.
                return unsafe { normalize_sse41(positions, norm_offset) };
            }
        }

        #[cfg(all(feature = "std", feature = "optimization", target_arch = "aarch64"))]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                // SAFETY: We've checked that the CPU supports NEON.
                return unsafe { normalize_neon(positions, norm_offset) };
            }
        }

        normalize_scalar(positions, norm_offset);
    }

    pub(crate) fn find_matches(&mut self) {
        self.match_finder
            .find_matches(&mut self.data, &mut self.matches)
    }

    pub(crate) fn matches(&mut self) -> &mut Matches {
        &mut self.matches
    }

    pub(crate) fn skip(&mut self, len: usize) {
        self.match_finder.skip(&mut self.data, len)
    }

    pub(crate) fn set_preset_dict(&mut self, dict_size: u32, preset_dict: &[u8]) {
        self.data
            .set_preset_dict(dict_size, preset_dict, &mut self.match_finder)
    }

    pub(crate) fn set_finishing(&mut self) {
        self.data.set_finishing(&mut self.match_finder)
    }

    pub(crate) fn fill_window(&mut self, input: &[u8]) -> usize {
        self.data.fill_window(input, &mut self.match_finder)
    }

    pub(crate) fn set_flushing(&mut self) {
        self.data.set_flushing(&mut self.match_finder)
    }

    pub(crate) fn verify_matches(&self) -> bool {
        self.data.verify_matches(&self.matches)
    }
}

impl LzEncoderData {
    pub(crate) fn is_started(&self) -> bool {
        self.read_pos != -1
    }

    pub(crate) fn read_buffer(&self) -> &[u8] {
        &self.buf[self.read_pos as usize..]
    }

    fn set_preset_dict(
        &mut self,
        dict_size: u32,
        preset_dict: &[u8],
        match_finder: &mut dyn MatchFind,
    ) {
        debug_assert!(!self.is_started());
        debug_assert_eq!(self.write_pos, 0);
        let copy_size = preset_dict.len().min(dict_size as usize);
        let offset = preset_dict.len() - copy_size;
        self.buf[0..copy_size].copy_from_slice(&preset_dict[offset..(offset + copy_size)]);
        self.write_pos += copy_size as i32;
        match_finder.skip(self, copy_size);
    }

    fn move_window(&mut self) {
        let move_offset =
            (self.read_pos + 1 - self.keep_size_before as i32) & MOVE_BLOCK_ALIGN_MASK;
        let move_size = self.write_pos - move_offset;

        debug_assert!(move_size >= 0);
        debug_assert!(move_offset >= 0);

        let move_size = move_size as usize;
        let offset = move_offset as usize;

        self.buf.copy_within(offset..offset + move_size, 0);

        self.read_pos -= move_offset;
        self.read_limit -= move_offset;
        self.write_pos -= move_offset;
    }

    fn fill_window(&mut self, input: &[u8], match_finder: &mut dyn MatchFind) -> usize {
        debug_assert!(!self.finishing);
        if self.read_pos >= (self.buf_size as i32 - self.keep_size_after as i32) {
            self.move_window();
        }
        let len = if input.len() as i32 > self.buf_size as i32 - self.write_pos {
            (self.buf_size as i32 - self.write_pos) as usize
        } else {
            input.len()
        };
        let d_start = self.write_pos as usize;
        let d_end = d_start + len;
        self.buf[d_start..d_end].copy_from_slice(&input[..len]);
        self.write_pos += len as i32;
        if self.write_pos >= self.keep_size_after as i32 {
            self.read_limit = self.write_pos - self.keep_size_after as i32;
        }
        self.process_pending_bytes(match_finder);
        len
    }

    fn process_pending_bytes(&mut self, match_finder: &mut dyn MatchFind) {
        if self.pending_size > 0 && self.read_pos < self.read_limit {
            self.read_pos -= self.pending_size as i32;
            let old_pending = self.pending_size;
            self.pending_size = 0;
            match_finder.skip(self, old_pending as _);
            debug_assert!(self.pending_size <= old_pending);
        }
    }

    fn set_flushing(&mut self, match_finder: &mut dyn MatchFind) {
        self.read_limit = self.write_pos - 1;
        self.process_pending_bytes(match_finder);
    }

    fn set_finishing(&mut self, match_finder: &mut dyn MatchFind) {
        self.read_limit = self.write_pos - 1;
        self.finishing = true;
        self.process_pending_bytes(match_finder);
    }

    pub fn has_enough_data(&self, already_read_len: i32) -> bool {
        self.read_pos - already_read_len < self.read_limit
    }

    pub(crate) fn copy_uncompressed<W: Write>(
        &self,
        out: &mut W,
        backward: i32,
        len: usize,
    ) -> crate::Result<()> {
        let start = (self.read_pos + 1 - backward) as usize;
        out.write_all(&self.buf[start..(start + len)])
    }

    #[inline(always)]
    pub(crate) fn get_avail(&self) -> i32 {
        debug_assert_ne!(self.read_pos, -1);
        self.write_pos - self.read_pos
    }

    #[inline(always)]
    pub(crate) fn get_pos(&self) -> i32 {
        self.read_pos
    }

    #[inline(always)]
    pub(crate) fn get_byte(&self, forward: i32, backward: i32) -> u8 {
        self.buf[(self.read_pos + forward - backward) as usize]
    }

    #[inline(always)]
    pub(crate) fn get_byte_by_pos(&self, pos: i32) -> u8 {
        self.buf[pos as usize]
    }

    #[inline(always)]
    pub(crate) fn get_byte_backward(&self, backward: i32) -> u8 {
        self.buf[(self.read_pos - backward) as usize]
    }

    #[inline(always)]
    pub(crate) fn get_current_byte(&self) -> u8 {
        self.buf[self.read_pos as usize]
    }

    #[inline(always)]
    pub(crate) fn get_match_len(&self, dist: i32, len_limit: i32) -> usize {
        extend_match(&self.buf, self.read_pos, 0, dist + 1, len_limit) as usize
    }

    #[inline(always)]
    pub(crate) fn get_match_len2(&self, forward: i32, dist: i32, len_limit: i32) -> u32 {
        if len_limit <= 0 {
            return 0;
        }
        extend_match(&self.buf, self.read_pos + forward, 0, dist + 1, len_limit) as u32
    }

    #[inline(always)]
    pub(crate) fn get_match_len_fast_reject<const MATCH_LEN_MIN: usize>(
        &self,
        dist: i32,
        len_limit: i32,
    ) -> usize {
        let match_dist = dist + 1;
        let read_pos = self.read_pos as usize;

        // Fast rejection
        #[cfg(feature = "optimization")]
        unsafe {
            // SAFETY: We clamp the read positions in range of the buffer.
            let clamped0 = read_pos.min(self.buf_limit_u16);
            let clamped1 = (read_pos - match_dist as usize).min(self.buf_limit_u16);

            if core::ptr::read_unaligned(self.buf.as_ptr().add(clamped0) as *const u16)
                != core::ptr::read_unaligned(self.buf.as_ptr().add(clamped1) as *const u16)
            {
                return 0;
            }
        }
        #[cfg(not(feature = "optimization"))]
        if self.buf[read_pos] != self.buf[read_pos - match_dist as usize]
            || self.buf[read_pos + 1] != self.buf[read_pos + 1 - match_dist as usize]
        {
            return 0;
        }

        extend_match(&self.buf, self.read_pos, 2, match_dist, len_limit) as usize
    }

    fn verify_matches(&self, matches: &Matches) -> bool {
        let len_limit = self.get_avail().min(self.match_len_max as i32);

        for i in 0..matches.count as usize {
            let match_distance = matches.dist[i] + 1;
            let actual_len = extend_match(&self.buf, self.read_pos, 0, match_distance, len_limit);

            if actual_len as u32 != matches.len[i] {
                return false;
            }
        }

        true
    }

    pub(crate) fn move_pos(
        &mut self,
        required_for_flushing: i32,
        required_for_finishing: i32,
    ) -> i32 {
        debug_assert!(required_for_flushing >= required_for_finishing);
        self.read_pos += 1;
        let mut avail = self.write_pos - self.read_pos;
        if avail < required_for_flushing && (avail < required_for_finishing || !self.finishing) {
            self.pending_size += 1;
            avail = 0;
        }
        avail
    }
}

impl Deref for LzEncoder {
    type Target = LzEncoderData;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

fn get_buf_size(
    dict_size: u32,
    extra_size_before: u32,
    extra_size_after: u32,
    match_len_max: u32,
) -> u32 {
    let keep_size_before = extra_size_before + dict_size;
    let keep_size_after = extra_size_after + match_len_max;
    let reserve_size = (dict_size / 2 + (256 << 10)).min(512 << 20);
    keep_size_before + keep_size_after + reserve_size
}

/// Positions not newer than `norm_offset` must clamp to `0` (the "no position"
/// marker). `saturating_sub` would saturate at [`i32::MIN`] instead, and the
/// distance calculations in the match finders would then overflow into
/// out-of-bounds buffer indices.
#[inline(always)]
fn normalize_scalar(positions: &mut [i32], norm_offset: i32) {
    positions
        .iter_mut()
        .for_each(|p| *p = (*p).max(norm_offset) - norm_offset);
}

/// Normalization implementation using ARM NEON for 128-bit SIMD processing.
#[cfg(all(feature = "std", feature = "optimization", target_arch = "aarch64"))]
#[target_feature(enable = "neon")]
unsafe fn normalize_neon(positions: &mut [i32], norm_offset: i32) {
    unsafe {
        use core::arch::aarch64::*;

        // Create a 128-bit vector with the offset broadcast to all 4 lanes.
        let norm_v = vdupq_n_s32(norm_offset);

        // Split the slice into a 16-byte aligned middle part and unaligned ends.
        // `int32x4_t` is the NEON vector type for 4 x i32, which is 16 bytes.
        let (prefix, chunks, suffix) = positions.align_to_mut::<int32x4_t>();

        normalize_scalar(prefix, norm_offset);

        for chunk in chunks {
            let ptr = chunk as *mut int32x4_t as *mut i32;

            let data = vld1q_s32(ptr);

            // Perform saturated subtraction on 8 integers simultaneously.
            let max_val = vmaxq_s32(data, norm_v);
            let result = vsubq_s32(max_val, norm_v);

            vst1q_s32(ptr, result);
        }

        normalize_scalar(suffix, norm_offset);
    }
}

/// Normalization implementation using AVX2 for 256-bit SIMD processing.
#[cfg(all(feature = "std", feature = "optimization", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn normalize_avx2(positions: &mut [i32], norm_offset: i32) {
    unsafe {
        use core::arch::x86_64::*;

        // Create a 256-bit vector with the normalization offset broadcast to all 8 lanes.
        let norm_v = _mm256_set1_epi32(norm_offset);

        // Split the slice into a 32-byte aligned middle part and unaligned ends.
        let (prefix, chunks, suffix) = positions.align_to_mut::<__m256i>();

        normalize_scalar(prefix, norm_offset);

        for chunk in chunks {
            // Use ALIGNED load. This is safe because `align_to_mut`
            // guarantees that `chunk` is aligned to 32 bytes.
            let data = _mm256_load_si256(chunk as *mut _);

            // Perform saturated subtraction on 8 integers simultaneously.
            let max_val = _mm256_max_epi32(data, norm_v);
            let result = _mm256_sub_epi32(max_val, norm_v);

            // Use ALIGNED store to write the results back.
            _mm256_store_si256(chunk as *mut _, result);
        }

        normalize_scalar(suffix, norm_offset);
    }
}

/// Normalization implementation using SSE4.1 for 128-bit SIMD processing.
#[cfg(all(feature = "std", feature = "optimization", target_arch = "x86_64"))]
#[target_feature(enable = "sse4.1")]
unsafe fn normalize_sse41(positions: &mut [i32], norm_offset: i32) {
    unsafe {
        use core::arch::x86_64::*;

        // Create a 128-bit vector with the offset broadcast to all 4 lanes.
        let norm_v = _mm_set1_epi32(norm_offset);

        // Split the slice into a 16-byte aligned middle part and unaligned ends.
        let (prefix, chunks, suffix) = positions.align_to_mut::<__m128i>();

        normalize_scalar(prefix, norm_offset);

        // Process the aligned middle part in 128-bit (4 x i32) chunks.
        for chunk in chunks {
            // Use ALIGNED 128-bit load.
            let data = _mm_load_si128(chunk as *mut _);

            let max_val = _mm_max_epi32(data, norm_v);
            let result = _mm_sub_epi32(max_val, norm_v);

            // Use ALIGNED 128-bit store.
            _mm_store_si128(chunk as *mut _, result);
        }

        normalize_scalar(suffix, norm_offset);
    }
}
