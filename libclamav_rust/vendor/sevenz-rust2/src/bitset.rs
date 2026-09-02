use std::fmt;
#[cfg(feature = "compress")]
use std::io::Write;

/// A set of usize values represented as a bit vector.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct BitSet {
    /// We use a Vec<usize> to store the bits, where each usize represents usize::BITS.
    bits: Vec<usize>,
    /// The number of bits in the set (not the number of set bits).
    bit_count: usize,
}

impl BitSet {
    /// Returns a new [`BitSet`].
    pub(crate) fn new() -> Self {
        Self {
            bits: Vec::new(),
            bit_count: 0,
        }
    }

    /// Returns a new [`BitSet`] with the initial capacity for `count` elements.
    pub(crate) fn with_capacity(bit_count: usize) -> Self {
        let num_blocks = Self::blocks_for_bits(bit_count);
        let bits = vec![0; num_blocks];
        Self { bits, bit_count }
    }

    /// Returns the number of set bits in this set.
    pub(crate) fn len(&self) -> usize {
        self.bits
            .iter()
            .map(|&block| block.count_ones() as usize)
            .sum()
    }

    /// Returns `true` if this set contains the specified value.
    pub(crate) fn contains(&self, value: usize) -> bool {
        if value >= self.bit_count {
            return false;
        }

        let (block_idx, bit_idx) = self.bit_indices(value);
        if block_idx >= self.bits.len() {
            return false;
        }

        (self.bits[block_idx] & (1 << bit_idx)) != 0
    }

    /// Adds a value to the set.
    ///
    /// Returns `false` if the value was already present in the set.
    pub(crate) fn insert(&mut self, value: usize) -> bool {
        if self.contains(value) {
            return false;
        }

        if value >= self.bit_count {
            self.grow(value + 1);
        }

        let (block_idx, bit_idx) = self.bit_indices(value);
        self.bits[block_idx] |= 1 << bit_idx;

        true
    }

    /// Removes a value from the set.
    ///
    /// Returns `true` if the value was present in the set.
    pub(crate) fn remove(&mut self, value: usize) -> bool {
        if !self.contains(value) {
            return false;
        }

        let (block_idx, bit_idx) = self.bit_indices(value);
        self.bits[block_idx] &= !(1 << bit_idx);

        true
    }

    /// Computes how many blocks are needed to store that many bits.
    fn blocks_for_bits(bits: usize) -> usize {
        if bits == 0 {
            return 0;
        }
        (bits - 1) / usize::BITS as usize + 1
    }

    /// Computes the block index and bit index for a given bit position.
    fn bit_indices(&self, bit_pos: usize) -> (usize, usize) {
        (
            bit_pos / usize::BITS as usize,
            bit_pos % usize::BITS as usize,
        )
    }

    /// Grows the bit vector to accommodate at least `new_len` bits.
    fn grow(&mut self, new_len: usize) {
        if new_len <= self.bit_count {
            return;
        }

        let old_num_blocks = self.bits.len();
        let new_num_blocks = Self::blocks_for_bits(new_len);

        if new_num_blocks > old_num_blocks {
            self.bits.resize(new_num_blocks, 0);
        }

        self.bit_count = new_len;
    }

    /// Reserves the minimum capacity for the given `BitSet` to contain `count` distinct elements.
    pub(crate) fn reserve_len_exact(&mut self, count: usize) {
        if count > self.bit_count {
            let new_num_blocks = Self::blocks_for_bits(count);
            let old_num_blocks = self.bits.len();

            if new_num_blocks > old_num_blocks {
                self.bits.reserve_exact(new_num_blocks - old_num_blocks);
                self.bits.resize(new_num_blocks, 0);
            }

            self.bit_count = count;
        }
    }
}

impl Default for BitSet {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for BitSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BitSet({})", self.bit_count)
    }
}

#[cfg(feature = "compress")]
pub(crate) fn write_bit_set<W: Write>(mut write: W, bs: &BitSet) -> std::io::Result<()> {
    use crate::ByteWriter;

    let mut cache = 0;
    let mut shift = 7;
    for i in 0..bs.bit_count {
        let set = if bs.contains(i) { 1 } else { 0 };
        cache |= set << shift;
        shift -= 1;
        if shift < 0 {
            write.write_u8(cache)?;
            shift = 7;
            cache = 0;
        }
    }
    if shift != 7 {
        write.write_u8(cache)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitset_basic() {
        let mut bs = BitSet::new();
        assert_eq!(bs.len(), 0);

        assert!(bs.insert(0));
        assert!(bs.insert(3));
        assert!(bs.insert(7));
        assert!(!bs.insert(3));

        assert_eq!(bs.len(), 3);

        assert!(bs.contains(0));
        assert!(!bs.contains(1));
        assert!(!bs.contains(2));
        assert!(bs.contains(3));
        assert!(!bs.contains(4));
        assert!(!bs.contains(5));
        assert!(!bs.contains(6));
        assert!(bs.contains(7));

        assert!(bs.remove(3));
        assert!(!bs.remove(3));
        assert!(!bs.contains(3));
        assert_eq!(bs.len(), 2);
    }

    #[test]
    fn test_bitset_with_capacity() {
        let mut bs = BitSet::with_capacity(100);
        assert_eq!(bs.len(), 0);

        bs.insert(150);
        assert!(bs.contains(150));
    }

    #[test]
    fn test_bitset_bit_count() {
        let mut bs = BitSet::new();
        bs.insert(0);
        bs.insert(10);
        bs.insert(63);

        assert!(bs.bit_count >= 64);
    }

    #[test]
    #[cfg(feature = "compress")]
    fn test_bitset_serialization() {
        let mut bs = BitSet::new();
        bs.insert(0);
        bs.insert(3);
        bs.insert(7);
        bs.insert(8);
        bs.insert(15);

        let mut buffer = Vec::new();
        write_bit_set(&mut buffer, &bs).unwrap();

        assert_eq!(buffer, vec![0b10010001, 0b10000001]);

        let deserialized = read_bits_test(&mut buffer.as_slice(), 16).unwrap();
        assert!(deserialized.contains(0));
        assert!(!deserialized.contains(1));
        assert!(!deserialized.contains(2));
        assert!(deserialized.contains(3));
        assert!(!deserialized.contains(4));
        assert!(!deserialized.contains(5));
        assert!(!deserialized.contains(6));
        assert!(deserialized.contains(7));
        assert!(deserialized.contains(8));
        assert!(!deserialized.contains(9));
        assert!(!deserialized.contains(14));
        assert!(deserialized.contains(15));
    }

    #[cfg(feature = "compress")]
    fn read_bits_test<R: std::io::Read>(
        reader: &mut R,
        size: usize,
    ) -> Result<BitSet, std::io::Error> {
        let mut bits = BitSet::with_capacity(size);
        let mut mask = 0u32;
        let mut cache = 0u32;
        for i in 0..size {
            if mask == 0 {
                mask = 0x80;
                let mut buf = [0];
                reader.read_exact(&mut buf)?;
                cache = buf[0] as u32;
            }
            if (cache & mask) != 0 {
                bits.insert(i);
            }
            mask >>= 1;
        }
        Ok(bits)
    }
}
