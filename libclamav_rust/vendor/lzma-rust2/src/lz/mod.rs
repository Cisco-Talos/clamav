mod bt4;
mod hash234;
mod hc4;
mod lz_decoder;
mod lz_encoder;

pub(crate) use lz_decoder::*;
pub use lz_encoder::*;

/// Extends a match to its maximum possible length within a specified limit.
#[inline(always)]
fn extend_match(buf: &[u8], read_pos: i32, current_len: i32, distance: i32, limit: i32) -> i32 {
    let start1 = (read_pos + current_len) as usize;
    let start2 = start1 - distance as usize;

    #[cfg(not(feature = "optimization"))]
    let (s1, s2) = {
        let extension_limit = (limit - current_len) as usize;
        (
            &buf[start1..start1 + extension_limit],
            &buf[start2..start2 + extension_limit],
        )
    };

    #[cfg(feature = "optimization")]
    let (s1, s2) = unsafe {
        let logical_extension = (limit - current_len) as usize;
        let physical_extension = buf.len().saturating_sub(start1);
        let extension_limit = logical_extension.min(physical_extension);

        // SAFETY: The `extension_limit` calculation above provides the guarantee
        // that these slices are in-bounds.
        (
            buf.get_unchecked(start1..start1 + extension_limit),
            buf.get_unchecked(start2..start2 + extension_limit),
        )
    };

    let extension = extend_match_safe(s1, s2) as i32;

    current_len + extension
}

/// Extends a match to its maximum possible length within a specified limit.
///
/// This function is optimized using native word-at-a-time comparisons.
#[cfg(not(feature = "optimization"))]
#[inline(always)]
fn extend_match_safe(s1: &[u8], s2: &[u8]) -> usize {
    const WORD_SIZE: usize = size_of::<usize>();

    let len = s1.len().min(s2.len());

    let mut matched = 0;

    while matched + WORD_SIZE <= len {
        let s1_slice = &s1[matched..matched + WORD_SIZE];
        let s2_slice = &s2[matched..matched + WORD_SIZE];

        let s1_array: [u8; WORD_SIZE] = s1_slice.try_into().unwrap();
        let s2_array: [u8; WORD_SIZE] = s2_slice.try_into().unwrap();

        let word1 = usize::from_ne_bytes(s1_array);
        let word2 = usize::from_ne_bytes(s2_array);

        if word1 == word2 {
            matched += WORD_SIZE;
        } else {
            let diff_bits = word1 ^ word2;

            #[cfg(target_endian = "little")]
            let matching_bytes = (diff_bits.trailing_zeros() / 8) as usize;

            #[cfg(target_endian = "big")]
            let matching_bytes = (diff_bits.leading_zeros() / 8) as usize;

            return matched + matching_bytes;
        }
    }

    while matched < len && s1[matched] == s2[matched] {
        matched += 1;
    }

    matched
}

/// Extends a match between two slices to its maximum possible length.
///
/// This function is optimized using native word-at-a-time comparisons.
#[cfg(feature = "optimization")]
#[inline(always)]
fn extend_match_safe(s1: &[u8], s2: &[u8]) -> usize {
    const WORD_SIZE: usize = size_of::<usize>();

    let len = s1.len().min(s2.len());

    // SAFETY: This is safe because all pointer accesses are bounded by
    // `len`, which is calculated from the lengths of the input slices,
    // ensuring no out-of-bounds reads.
    unsafe {
        let mut ptr1 = s1.as_ptr();
        let mut ptr2 = s2.as_ptr();

        let mut extended_len = 0;

        while extended_len + WORD_SIZE <= len {
            let word1 = (ptr1 as *const usize).read_unaligned();
            let word2 = (ptr2 as *const usize).read_unaligned();

            if word1 == word2 {
                extended_len += WORD_SIZE;
                ptr1 = ptr1.add(WORD_SIZE);
                ptr2 = ptr2.add(WORD_SIZE);
            } else {
                let diff_bits = word1 ^ word2;

                #[cfg(all(
                    target_endian = "little",
                    not(all(target_arch = "x86_64", target_feature = "bmi1"))
                ))]
                let matching_bytes = (diff_bits.trailing_zeros() / 8) as usize;

                #[cfg(all(
                    target_endian = "little",
                    all(target_arch = "x86_64", target_feature = "bmi1")
                ))]
                let matching_bytes =
                    (core::arch::x86_64::_tzcnt_u64(diff_bits as u64) / 8) as usize;

                #[cfg(target_endian = "big")]
                let matching_bytes = (diff_bits.leading_zeros() / 8) as usize;

                return extended_len + matching_bytes;
            }
        }

        while extended_len < len && *ptr1 == *ptr2 {
            extended_len += 1;
            ptr1 = ptr1.add(1);
            ptr2 = ptr2.add(1);
        }

        extended_len
    }
}
