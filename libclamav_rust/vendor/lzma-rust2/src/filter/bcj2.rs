//! The BCJ2 filter is a branch converter for 32-bit x86 executables (version 2).

mod decode;

use alloc::{vec, vec::Vec};

use decode::Bcj2Decoder;

use crate::{Read, error_invalid_data};

const BUF_SIZE: usize = 1 << 18;

const BCJ2_NUM_STREAMS: usize = 4;

const BCJ2_STREAM_MAIN: usize = 0;

const BCJ2_STREAM_CALL: usize = 1;

const BCJ2_STREAM_JUMP: usize = 2;

const BCJ2_STREAM_RC: usize = 3;

const BCJ2_DEC_STATE_ORIG_0: usize = BCJ2_NUM_STREAMS;

const BCJ2_DEC_STATE_ORIG_3: usize = BCJ2_NUM_STREAMS + 3;

const BCJ2_DEC_STATE_ORIG: usize = BCJ2_NUM_STREAMS + 4;

const BCJ2_DEC_STATE_OK: usize = BCJ2_NUM_STREAMS + 5;

const NUM_MODEL_BITS: u16 = 11;

const BIT_MODEL_TOTAL: u16 = 1 << NUM_MODEL_BITS;

const NUM_MOVE_BITS: u16 = 5;

const K_TOP_VALUE: u32 = 1 << 24;

#[inline(always)]
const fn bcj2_is_32bit_stream(s: usize) -> bool {
    (s) == BCJ2_STREAM_CALL || (s) == BCJ2_STREAM_JUMP
}

/// BCJ2 coder for x86 executables with separate streams for different instruction types.
pub struct Bcj2Coder {
    bufs: Vec<u8>,
}

impl Bcj2Coder {
    fn buf_at(&mut self, i: usize) -> &mut [u8] {
        let i = i * BUF_SIZE;
        &mut self.bufs[i..i + BUF_SIZE]
    }
}

impl Default for Bcj2Coder {
    fn default() -> Self {
        let buf_len = BUF_SIZE * (BCJ2_NUM_STREAMS);
        Self {
            bufs: vec![0; buf_len],
        }
    }
}

/// Reader for BCJ2-filtered data with multiple input streams.
pub struct Bcj2Reader<R> {
    base: Bcj2Coder,
    inputs: Vec<R>,
    decoder: Bcj2Decoder,
    extra_read_sizes: [usize; BCJ2_NUM_STREAMS],
    read_res: [bool; BCJ2_NUM_STREAMS],
    uncompressed_size: u64,
}

impl<R> Bcj2Reader<R> {
    /// Creates a new BCJ2 reader with the given input streams and expected output size.
    pub fn new(inputs: Vec<R>, uncompressed_size: u64) -> Self {
        Self {
            base: Default::default(),
            inputs,
            decoder: Bcj2Decoder::new(),
            extra_read_sizes: [0; BCJ2_NUM_STREAMS],
            read_res: [true; BCJ2_NUM_STREAMS],
            uncompressed_size,
        }
        .init()
    }

    fn init(mut self) -> Self {
        let mut v = 0;
        for i in 0..BCJ2_NUM_STREAMS {
            self.decoder.bufs[i] = v;
            self.decoder.lims[i] = v;
            v += BUF_SIZE;
        }

        self
    }
}

impl<R: Read> Read for Bcj2Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
        let mut dest_buf = buf;
        if dest_buf.len() > self.uncompressed_size as usize {
            dest_buf = &mut dest_buf[..self.uncompressed_size as usize];
        }
        if dest_buf.is_empty() {
            return Ok(0);
        }
        let mut result_size = 0;
        self.decoder.set_dest(0);
        let mut offset = 0;
        loop {
            if !self.decoder.decode(&mut self.base.bufs, dest_buf) {
                return Err(error_invalid_data("bcj2 decode error"));
            }

            {
                let cur_size = self.decoder.dest() - offset;
                if cur_size != 0 {
                    result_size += cur_size;
                    self.uncompressed_size -= cur_size as u64;
                    offset += cur_size;
                }
            }

            if self.decoder.state >= BCJ2_NUM_STREAMS {
                break;
            }
            let mut total_read = self.extra_read_sizes[self.decoder.state];
            {
                let buf_index = self.decoder.state * BUF_SIZE;
                let from = self.decoder.bufs[self.decoder.state];
                for i in 0..total_read {
                    let b = self.base.bufs[from + i];
                    self.base.bufs[buf_index + i] = b;
                }
                self.decoder.lims[self.decoder.state] = buf_index;
                self.decoder.bufs[self.decoder.state] = buf_index;
            }
            if !self.read_res[self.decoder.state] {
                return Err(error_invalid_data("bcj2 decode error:2"));
            }

            loop {
                let cur_size = BUF_SIZE - total_read;
                let cur_size = self.inputs[self.decoder.state].read(
                    &mut self.base.buf_at(self.decoder.state)[total_read..total_read + cur_size],
                )?;
                if cur_size == 0 {
                    break;
                }
                total_read += cur_size;
                if !(total_read < 4 && bcj2_is_32bit_stream(self.decoder.state)) {
                    break;
                }
            }

            if total_read == 0 {
                break;
            }

            if bcj2_is_32bit_stream(self.decoder.state) {
                let extra_size = total_read & 3;
                self.extra_read_sizes[self.decoder.state] = extra_size;
                if total_read < 4 {
                    if result_size != 0 {
                        return Ok(result_size);
                    }
                    return Err(error_invalid_data("bcj2 decode error:3"));
                }
                total_read -= extra_size;
            }
            self.decoder.lims[self.decoder.state] = total_read + self.decoder.state * BUF_SIZE;
        }

        if self.uncompressed_size == 0 {
            if self.decoder.code != 0 {
                return Err(error_invalid_data("bcj2 decode error:4"));
            }
            if self.decoder.state != BCJ2_STREAM_MAIN && self.decoder.state != BCJ2_DEC_STATE_ORIG {
                return Err(error_invalid_data("bcj2 decode error:5"));
            }
        }
        Ok(result_size)
    }
}
