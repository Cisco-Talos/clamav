use alloc::{vec, vec::Vec};

use crate::{
    BIT_MODEL_TOTAL_BITS, ByteReader, MOVE_BITS, RC_BIT_MODEL_OFFSET, Read, SHIFT_BITS, error_eof,
    error_invalid_data, error_invalid_input, error_other,
};

pub(crate) struct RangeDecoder<R> {
    inner: R,
    range: u32,
    code: u32,
}

/// The persistent part of a range decoder: everything except the byte source.
///
/// A sans-I/O decoder cannot own its byte source: the input is a slice borrowed
/// from the caller, and only for one `process()` call. Keeping `{range, code}`
/// apart from it lets such a decoder build a fresh [`RangeDecoder`] each call.
#[derive(Clone, Copy, Default)]
pub(crate) struct RangeCoderState {
    pub(crate) range: u32,
    pub(crate) code: u32,
}

impl<R> RangeDecoder<R> {
    pub(crate) fn from_parts(inner: R, state: RangeCoderState) -> Self {
        Self {
            inner,
            range: state.range,
            code: state.code,
        }
    }

    pub(crate) fn state(&self) -> RangeCoderState {
        RangeCoderState {
            range: self.range,
            code: self.code,
        }
    }

    pub(crate) fn into_inner(self) -> R {
        self.inner
    }

    pub(crate) fn inner(&self) -> &R {
        &self.inner
    }

    pub(crate) fn inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

impl RangeDecoder<RangeDecoderBuffer> {
    pub(crate) fn new_buffer(size: usize) -> Self {
        Self {
            inner: RangeDecoderBuffer::new(size - 5),
            code: 0,
            range: 0,
        }
    }
}

impl<R: RangeReader> RangeDecoder<R> {
    pub(crate) fn new_stream(mut inner: R) -> crate::Result<Self> {
        let b = inner.try_read_u8()?;
        if b != 0x00 {
            return Err(error_invalid_input("range decoder first byte is not zero"));
        }
        let code = inner.read_u32_be()?;
        Ok(Self {
            inner,
            code,
            range: 0xFFFFFFFFu32,
        })
    }

    pub(crate) fn is_stream_finished(&self) -> bool {
        self.code == 0
    }

    /// See [`RangeReader::can_start_symbol`].
    #[inline(always)]
    pub(crate) fn can_start_symbol(&self) -> bool {
        self.inner.can_start_symbol()
    }

    /// See [`RangeReader::can_normalize`].
    #[inline(always)]
    pub(crate) fn can_normalize(&self) -> bool {
        self.inner.can_normalize()
    }
}

impl<R: RangeReader> RangeDecoder<R> {
    #[inline(always)]
    pub(crate) fn normalize(&mut self) {
        if self.range < 0x0100_0000 {
            let b = self.inner.read_u8() as u32;
            self.code = (self.code << SHIFT_BITS) | b;
            self.range <<= SHIFT_BITS;
        }
    }

    #[inline(always)]
    pub(crate) fn decode_bit(&mut self, prob: &mut u16) -> i32 {
        self.normalize();
        let bound = (self.range >> BIT_MODEL_TOTAL_BITS) * (*prob as u32);

        // This mask will be 0 for bit 0, and 0xFFFFFFFF for bit 1.
        let mask = 0u32.wrapping_sub((self.code >= bound) as u32);

        self.range = (bound & !mask) | ((self.range - bound) & mask);
        self.code -= bound & mask;

        let p = *prob as u32;
        let offset = RC_BIT_MODEL_OFFSET & !mask;
        *prob = p.wrapping_sub((p.wrapping_add(offset)) >> MOVE_BITS) as u16;

        (mask & 1) as i32
    }

    pub(crate) fn decode_bit_tree(&mut self, probs: &mut [u16]) -> i32 {
        let mut symbol = 1;
        loop {
            symbol = (symbol << 1) | self.decode_bit(&mut probs[symbol as usize]);
            if symbol >= probs.len() as i32 {
                break;
            }
        }
        symbol - probs.len() as i32
    }

    pub(crate) fn decode_reverse_bit_tree(&mut self, probs: &mut [u16]) -> i32 {
        let mut symbol = 1;
        let mut i = 0;
        let mut result = 0;
        loop {
            let bit = self.decode_bit(&mut probs[symbol as usize]);
            symbol = (symbol << 1) | bit;
            result |= bit << i;
            i += 1;
            if symbol >= probs.len() as i32 {
                break;
            }
        }
        result
    }

    /*
        /// This was the original function, which can't be optimized well
        /// by the x86_64 backend. aarch64 on the other hand optimizes it fine.
        pub(crate) fn decode_direct_bits(&mut self, count: u32) -> i32 {
            let mut result = 0;

            for _ in 0..count {
                self.normalize();
                self.range >>= 1;
                let t = (self.code.wrapping_sub(self.range)) >> 31;
                self.code -= self.range & (t.wrapping_sub(1));
                result = (result << 1) | (1u32.wrapping_sub(t));
            }

            result as _
        }
    */

    pub(crate) fn decode_direct_bits(&mut self, count: u32) -> i32 {
        #[cfg(all(feature = "optimization", target_arch = "aarch64"))]
        {
            if self.inner.is_buffer() && count > 0 {
                return self.decode_direct_bits_aarch64(count);
            }
        }

        #[cfg(all(feature = "optimization", target_arch = "x86_64"))]
        {
            if self.inner.is_buffer() && count > 0 {
                return self.decode_direct_bits_x86_64(count);
            }
        }

        // The following loop is the original function structured in a way,
        // that hopefully the compiler can optimize better.
        let mut result = 0;
        let mut count = count;

        'outer: loop {
            // Fast Path
            while self.range >= 0x0100_0000 {
                if count == 0 {
                    break 'outer;
                }
                count -= 1;

                self.range >>= 1;
                let t = self.code.wrapping_sub(self.range) >> 31;
                self.code -= self.range & t.wrapping_sub(1);
                result = (result << 1) | (1 - t);
            }

            if count == 0 {
                break 'outer;
            }

            // Slow Path
            let b = self.inner.read_u8() as u32;
            self.code = (self.code << SHIFT_BITS) | b;
            self.range <<= SHIFT_BITS;
        }

        result as _
    }

    #[cfg(all(feature = "optimization", target_arch = "aarch64"))]
    #[inline(always)]
    fn decode_direct_bits_aarch64(&mut self, count: u32) -> i32 {
        // Safety: It is critical that we clamp the reading from the buffer inside it bounds.
        // We also give the "nostack, readonly, pure" guarantees that we must not (and are not)
        // violate.
        unsafe {
            let mut result: i32 = 0;
            let mut pos = self.inner.pos();

            let buf = self.inner.buf();
            let buf_ptr = buf.as_ptr();
            let limit = buf.len() - 1;

            core::arch::asm!(r#"
                    // Setup constants
                    mov    {top_value_reg:w}, #{top_value}

                2:
                    // Calculate result = result << 1
                    lsl    {result:w}, {result:w}, #1

                    // Then, calculate the value for "bit == 1" case
                    orr    {result_bit1:w}, {result:w}, #1

                    // Normalize if range is below the top value
                    cmp    {range:w}, {top_value_reg:w}
                    b.hs   3f
                    lsl    {code:w}, {code:w}, #{shift_bits}
                    lsl    {range:w}, {range:w}, #{shift_bits}

                    // To prevent reading past the buffer, we clamp the read index
                    cmp    {pos}, {limit}
                    csel   {clamped_pos}, {limit}, {pos}, hi

                    // Read byte and update code using indexed addressing
                    ldrb   {tmp:w}, [{buf_ptr}, {clamped_pos}]
                    orr    {code:w}, {code:w}, {tmp:w}
                    add    {pos}, {pos}, #1

                3:
                    // Halve the range and check if code < new_range
                    // using a subtraction and flags
                    lsr    {range:w}, {range:w}, #1
                    subs   {tmp:w}, {code:w}, {range:w}

                    // Use CSEL to update code and result without branching
                    csel   {code:w}, {tmp:w}, {code:w}, hs
                    csel   {result:w}, {result_bit1:w}, {result:w}, hs

                    // Decrement loop counter and loop
                    subs   {count:w}, {count:w}, #1
                    b.ne   2b
                "#,
                // Main state registers (inputs and outputs)
                range = inout(reg) self.range,
                code = inout(reg) self.code,
                pos = inout(reg) pos,
                count = inout(reg) count => _,
                result = inout(reg) result,
                // Read-only inputs
                buf_ptr = in(reg) buf_ptr,
                limit = in(reg) limit,
                // Scratch registers
                top_value_reg = out(reg) _,
                clamped_pos = out(reg) _,
                result_bit1 = out(reg) _,
                tmp = out(reg) _,
                // Constants
                top_value = const 0x0100_0000,
                shift_bits = const SHIFT_BITS,
                // Compiler hints
                options(nostack, readonly, pure)
            );

            // We clamp to the size of the buffer because `pos == buf.len()` signals
            // that there is nothing more to read.
            self.inner.set_pos(pos.min(buf.len()));

            result
        }
    }

    #[cfg(all(feature = "optimization", target_arch = "x86_64"))]
    #[inline(always)]
    fn decode_direct_bits_x86_64(&mut self, count: u32) -> i32 {
        // Safety: It is critical that we clamp the reading from the buffer inside it bounds.
        // We also give the "nostack, readonly, pure" guarantees that we must not (and are not)
        // violate.
        unsafe {
            let mut result: i32 = 0;
            let mut pos = self.inner.pos();

            let buf = self.inner.buf();
            let buf_ptr = buf.as_ptr();
            let limit = buf.len() - 1;

            core::arch::asm!(r#"
                2:
                    // First, calculate result = result << 1
                    shl    {result:e}, 1

                    // Then, calculate the value for "bit == 1" case
                    lea    {result_bit1:e}, [{result:e} + 1]

                    // Normalize if range is below the top value
                    cmp    {range:e}, {top_value}
                    jae    3f
                    shl    {code:e}, {shift_bits}
                    shl    {range:e}, {shift_bits}

                    // To prevent reading past the buffer, clamp the read index
                    mov    {clamped_pos}, {pos}
                    cmp    {clamped_pos}, {limit}
                    cmovg  {clamped_pos}, {limit}

                    // Read byte and update code
                    movzx  {tmp_byte:e}, byte ptr [{buf_ptr} + {clamped_pos}]
                    or     {code:e}, {tmp_byte:e}
                    inc    {pos}

                3:
                    // Halve the range and check if code < new_range
                    // using a subtraction and the sign flag (SF).
                    shr    {range:e}, 1
                    mov    {tmp_code:e}, {code:e}
                    sub    {code:e}, {range:e}

                    // Use CMOV to update code and result without branching
                    cmovs  {code:e}, {tmp_code:e}
                    cmovns {result:e}, {result_bit1:e}

                    // Decrement loop counter and loop
                    dec    {count:e}
                    jnz    2b
                "#,
                // Main state registers (inputs and outputs)
                range = inout(reg) self.range,
                code = inout(reg) self.code,
                pos = inout(reg) pos,
                count = inout(reg) count => _,
                result = inout(reg) result,
                // Read-only inputs
                buf_ptr = in(reg) buf_ptr,
                limit = in(reg) limit,
                // Scratch registers for temporaries
                tmp_code = out(reg) _,
                result_bit1 = out(reg) _,
                clamped_pos = out(reg) _,
                tmp_byte = out(reg) _,
                // Constants
                top_value = const 0x0100_0000,
                shift_bits = const SHIFT_BITS,
                // Compiler hints
                options(nostack, readonly, pure)
            );

            // We clamp to the size of the buffer because `pos == buf.len()` signals
            // that there is nothing more to read.
            self.inner.set_pos(pos.min(buf.len()));

            result
        }
    }
}

pub(crate) struct RangeDecoderBuffer {
    buf: Vec<u8>,
    pos: usize,
}

impl RangeDecoder<RangeDecoderBuffer> {
    pub(crate) fn prepare<R: Read + ByteReader>(
        &mut self,
        mut reader: R,
        len: usize,
    ) -> crate::Result<()> {
        if len < 5 {
            return Err(error_invalid_input("buffer len must >= 5"));
        }

        let b = reader.read_u8()?;
        if b != 0x00 {
            return Err(error_invalid_input("first byte is 0"));
        }
        self.code = reader.read_u32_be()?;

        self.range = 0xFFFFFFFFu32;
        let len = len - 5;
        let pos = self.inner.buf.len() - len;
        let end = pos + len;
        self.inner.pos = pos;
        reader.read_exact(&mut self.inner.buf[pos..end])
    }

    pub(crate) fn prepare_from_slice(&mut self, data: &[u8]) -> crate::Result<()> {
        if data.len() < 5 {
            return Err(error_invalid_input("buffer len must >= 5"));
        }

        if data[0] != 0x00 {
            return Err(error_invalid_input("first byte is 0"));
        }
        self.code = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

        self.range = 0xFFFFFFFFu32;
        let payload = &data[5..];
        let len = payload.len();
        let pos = self.inner.buf.len() - len;
        self.inner.pos = pos;
        self.inner.buf[pos..pos + len].copy_from_slice(payload);
        Ok(())
    }

    #[inline]
    pub(crate) fn is_finished(&self) -> bool {
        self.inner.pos == self.inner.buf.len() && self.code == 0
    }
}

impl RangeDecoderBuffer {
    pub(crate) fn new(len: usize) -> Self {
        Self {
            buf: vec![0; len],
            pos: len,
        }
    }
}

/// A [`RangeReader`] over a borrowed input slice that knows where it must stop.
///
/// A symbol can be up to 20 bytes long, and we can't stop decoding a symbol
/// halfway, so we may only start while 20 bytes are left. A symbol may start
/// only while `pos < symbol_limit`.
///
/// When a stream has less than 20 bytes at the end, the caller passes the last
/// real bytes followed by padding bytes. `real_len` stores the size of actual
/// data. If the reader reads those padding bytes, we know that the stream is
/// truncated.
pub(crate) struct SliceRangeReader<'a> {
    buf: &'a [u8],
    pos: usize,
    real_len: usize,
    symbol_limit: usize,
}

impl<'a> SliceRangeReader<'a> {
    /// `real_len` must not exceed `buf.len()`, and `symbol_limit` must leave
    /// room for a whole symbol: the last position one may start at is
    /// `symbol_limit - 1`, and a symbol reads up to 20 bytes, so
    /// `symbol_limit + 19 <= buf.len()`. A `symbol_limit` of 0 is fine too and
    /// means no symbol may start at all.
    pub(crate) fn new(buf: &'a [u8], real_len: usize, symbol_limit: usize) -> Self {
        debug_assert!(!buf.is_empty());
        debug_assert!(real_len <= buf.len());
        Self {
            buf,
            pos: 0,
            real_len,
            symbol_limit,
        }
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }
}

impl RangeReader for SliceRangeReader<'_> {
    #[inline(always)]
    fn read_u8(&mut self) -> u8 {
        // Out of bound reads return an 1, which is fine, since the
        // LZMA reader will then throw a "dist overflow" error. With a correct
        // `symbol_limit` this can't be reached from inside a symbol anyway.
        let byte = *self.buf.get(self.pos).unwrap_or(&1);
        self.pos += 1;
        byte
    }

    fn try_read_u8(&mut self) -> crate::Result<u8> {
        let byte = self.buf.get(self.pos).copied().ok_or_else(error_eof)?;
        self.pos += 1;
        Ok(byte)
    }

    #[inline(always)]
    fn read_u32_be(&mut self) -> crate::Result<u32> {
        let array: [u8; 4] = self
            .buf
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| error_invalid_data("not enough data for reading u32 BE bytes"))?
            .try_into()
            .map_err(|_| error_other("slice doesn't match array size for u32 BE bytes"))?;
        self.pos += 4;
        Ok(u32::from_be_bytes(array))
    }

    #[inline(always)]
    fn can_start_symbol(&self) -> bool {
        self.pos < self.symbol_limit
    }

    #[inline(always)]
    fn can_normalize(&self) -> bool {
        self.pos < self.real_len
    }

    #[inline(always)]
    fn is_buffer(&self) -> bool {
        // This check is what keeps the assembly paths safe. They compute
        // `buf.len() - 1`, which would wrap around on an empty slice, so an
        // empty buffer has to go down the plain Rust path instead. Do not
        // replace this with a plain `true`: `new()` only checks for an empty
        // buffer in debug builds.
        !self.buf.is_empty()
    }

    #[inline(always)]
    fn pos(&self) -> usize {
        self.pos
    }

    #[inline(always)]
    fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    #[inline(always)]
    fn buf(&self) -> &[u8] {
        self.buf
    }
}

pub(crate) trait RangeReader {
    fn read_u8(&mut self) -> u8;

    fn try_read_u8(&mut self) -> crate::Result<u8>;

    fn read_u32_be(&mut self) -> crate::Result<u32>;

    /// True when there is enough input left to decode a whole symbol.
    ///
    /// Only a reader over a borrowed slice can run out in the middle of one.
    /// Every other reader can always get another byte, so it returns a constant
    /// `true` and the check disappears from the hot loop.
    #[inline(always)]
    fn can_start_symbol(&self) -> bool {
        true
    }

    /// True when the lookahead read after the last symbol may take a byte.
    ///
    /// A reader over a borrowed slice says no once it has used up its input.
    /// Every other reader always has another byte to give.
    #[inline(always)]
    fn can_normalize(&self) -> bool {
        true
    }

    #[inline(always)]
    fn is_buffer(&self) -> bool {
        false
    }

    #[inline(always)]
    fn pos(&self) -> usize {
        unimplemented!("not a buffer reader")
    }

    #[inline(always)]
    fn set_pos(&mut self, _pos: usize) {
        unimplemented!("not a buffer reader")
    }

    #[inline(always)]
    fn buf(&self) -> &[u8] {
        unimplemented!("not a buffer reader")
    }
}

impl<T: Read> RangeReader for T {
    #[inline(always)]
    fn read_u8(&mut self) -> u8 {
        // Out of bound reads return an 1, which is fine, since the
        // LZMA reader will then throw a "dist overflow" error.
        // Not returning an error results in code that can be better
        // optimized in the hot path and overall 10% better decoding
        // performance.
        let mut buf = [0; 1];
        match self.read_exact(&mut buf) {
            Ok(_) => buf[0],
            Err(_) => 1,
        }
    }

    fn try_read_u8(&mut self) -> crate::Result<u8> {
        let mut buf = [0; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    #[inline(always)]
    fn read_u32_be(&mut self) -> crate::Result<u32> {
        let mut buf = [0; 4];
        self.read_exact(buf.as_mut())?;
        Ok(u32::from_be_bytes(buf))
    }
}

impl RangeReader for RangeDecoderBuffer {
    #[inline(always)]
    fn read_u8(&mut self) -> u8 {
        // Out of bound reads return an 1, which is fine, since the
        // LZMA reader will then throw a "dist overflow" error.
        // Not returning an error results in code that can be better
        // optimized in the hot path and overall 10% better decoding
        // performance.
        let byte = *self.buf.get(self.pos).unwrap_or(&1);
        self.pos += 1;
        byte
    }

    fn try_read_u8(&mut self) -> crate::Result<u8> {
        self.buf.get(self.pos).copied().ok_or_else(error_eof)
    }

    #[inline(always)]
    fn read_u32_be(&mut self) -> crate::Result<u32> {
        let array: [u8; 4] = self
            .buf
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| error_invalid_data("not enough data for reading u32 BE bytes"))?
            .try_into()
            .map_err(|_| error_other("slice doesn't match array size for u32 BE bytes"))?;
        let b = u32::from_be_bytes(array);
        self.pos += 4;
        Ok(b)
    }

    #[inline(always)]
    fn is_buffer(&self) -> bool {
        true
    }

    #[inline(always)]
    fn pos(&self) -> usize {
        self.pos
    }

    #[inline(always)]
    fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    #[inline(always)]
    fn buf(&self) -> &[u8] {
        self.buf.as_slice()
    }
}
