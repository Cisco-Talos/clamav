/*
 * Incremental LZMA interface for libclamav.
 *
 * Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates.
 * SPDX-License-Identifier: GPL-2.0-only
 */

use std::{
    ffi::c_void,
    mem,
    panic::{self, AssertUnwindSafe},
    ptr, slice,
};

use log::debug;
use lzma_rust2::{lzma_get_memory_usage_by_props, Action, LzmaStream, Status};

const RESULT_OK: i32 = 0;
const RESULT_DATA_ERROR: i32 = 1;
const STREAM_END: i32 = 2;

// Decoder dictionaries are controlled by untrusted stream properties. Keep them
// independently bounded even when a caller has not associated the raw stream
// with a cli_ctx yet.
const LZMA_MEMORY_LIMIT_KB: u32 = 128 * 1024;

struct LzmaState {
    header: Vec<u8>,
    header_len: usize,
    size_override: Option<u64>,
    decoder: Option<LzmaStream>,
}

impl LzmaState {
    fn new(size_override: u64) -> Self {
        // The legacy C API uses zero as a sentinel for an LZMA-alone stream,
        // whose 13-byte header carries its size. A nonzero override describes
        // a raw stream and leaves only the five property bytes to consume.
        let override_value = (size_override != 0).then_some(size_override);
        Self {
            header: Vec::with_capacity(if override_value.is_some() { 5 } else { 13 }),
            header_len: if override_value.is_some() { 5 } else { 13 },
            size_override: override_value,
            decoder: None,
        }
    }

    fn consume_header(&mut self, input: &mut &[u8]) -> Result<(), ()> {
        let remaining = self.header_len.checked_sub(self.header.len()).ok_or(())?;
        let take = remaining.min(input.len());
        self.header.extend_from_slice(&input[..take]);
        *input = &input[take..];
        if self.header.len() != self.header_len || self.decoder.is_some() {
            return Ok(());
        }

        let props = *self.header.first().ok_or(())?;
        let dict_size = u32::from_le_bytes(
            self.header
                .get(1..5)
                .ok_or(())?
                .try_into()
                .map_err(|_| ())?,
        );
        let memory_kb = lzma_get_memory_usage_by_props(dict_size, props).map_err(|_| ())?;
        if memory_kb > LZMA_MEMORY_LIMIT_KB {
            return Err(());
        }
        let uncompressed_size = match self.size_override {
            Some(size) => size,
            None => u64::from_le_bytes(
                self.header
                    .get(5..13)
                    .ok_or(())?
                    .try_into()
                    .map_err(|_| ())?,
            ),
        };
        self.decoder = Some(
            LzmaStream::new_with_props(uncompressed_size, props, dict_size, None)
                .map_err(|_| ())?,
        );
        Ok(())
    }
}

unsafe fn buffer_pair<'a>(
    next_in: *mut *mut u8,
    avail_in: *mut usize,
    next_out: *mut *mut u8,
    avail_out: *mut usize,
) -> Option<(&'a [u8], &'a mut [u8])> {
    if next_in.is_null() || avail_in.is_null() || next_out.is_null() || avail_out.is_null() {
        return None;
    }
    let input_len = unsafe { *avail_in };
    let output_len = unsafe { *avail_out };
    let input_ptr = unsafe { *next_in };
    let output_ptr = unsafe { *next_out };
    if (input_len != 0 && input_ptr.is_null()) || (output_len != 0 && output_ptr.is_null()) {
        return None;
    }
    let input = if input_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(input_ptr, input_len) }
    };
    let output = if output_len == 0 {
        &mut []
    } else {
        unsafe { slice::from_raw_parts_mut(output_ptr, output_len) }
    };
    Some((input, output))
}

unsafe fn advance_pair(
    next_in: *mut *mut u8,
    avail_in: *mut usize,
    consumed: usize,
    next_out: *mut *mut u8,
    avail_out: *mut usize,
    produced: usize,
) -> bool {
    unsafe {
        if consumed > *avail_in || produced > *avail_out {
            return false;
        }
        if consumed != 0 {
            *next_in = (*next_in).add(consumed);
        }
        *avail_in -= consumed;
        if produced != 0 {
            *next_out = (*next_out).add(produced);
        }
        *avail_out -= produced;
    }
    true
}

unsafe fn invalidate_state(state: *mut *mut c_void) {
    if state.is_null() {
        return;
    }
    let raw = unsafe { ptr::replace(state, ptr::null_mut()) };
    if !raw.is_null() {
        drop(unsafe { Box::from_raw(raw.cast::<LzmaState>()) });
    }
}

unsafe fn ffi_guard<T: Copy>(
    state: *mut *mut c_void,
    panic_result: T,
    operation: impl FnOnce() -> T,
) -> T {
    match panic::catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(payload) => {
            // A hostile panic payload may itself panic when dropped. Contain
            // that secondary panic; only its replacement payload is leaked.
            let dropping = panic::catch_unwind(AssertUnwindSafe(|| drop(payload)));
            if let Err(payload) = dropping {
                mem::forget(payload);
            }
            // Null the caller-visible state before dropping it. If a destructor
            // itself panics, contain that second panic as well and leave the C
            // caller with an invalidated state rather than a dangling pointer.
            let cleanup =
                panic::catch_unwind(AssertUnwindSafe(|| unsafe { invalidate_state(state) }));
            if let Err(payload) = cleanup {
                mem::forget(payload);
            }
            let logging = panic::catch_unwind(AssertUnwindSafe(|| {
                debug!("Panic in Rust raw-LZMA FFI operation")
            }));
            if let Err(payload) = logging {
                mem::forget(payload);
            }
            panic_result
        }
    }
}

unsafe fn rust_lzma_init_impl(
    state: *mut *mut c_void,
    size_override: u64,
    next_in: *mut *mut u8,
    avail_in: *mut usize,
) -> i32 {
    if state.is_null() || next_in.is_null() || avail_in.is_null() {
        return RESULT_DATA_ERROR;
    }
    if unsafe { (*state).is_null() } {
        unsafe { *state = Box::into_raw(Box::new(LzmaState::new(size_override))).cast() };
    }
    let decoder = unsafe { &mut *((*state).cast::<LzmaState>()) };
    let input_len = unsafe { *avail_in };
    let input_ptr = unsafe { *next_in };
    if input_len != 0 && input_ptr.is_null() {
        return RESULT_DATA_ERROR;
    }
    let mut input = if input_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(input_ptr, input_len) }
    };
    let before = input.len();
    if decoder.consume_header(&mut input).is_err() {
        return RESULT_DATA_ERROR;
    }
    let consumed = before - input.len();
    unsafe {
        if consumed != 0 {
            *next_in = (*next_in).add(consumed);
        }
        *avail_in -= consumed;
    }
    RESULT_OK
}

#[no_mangle]
pub unsafe extern "C" fn rust_lzma_init(
    state: *mut *mut c_void,
    size_override: u64,
    next_in: *mut *mut u8,
    avail_in: *mut usize,
) -> i32 {
    unsafe {
        ffi_guard(state, RESULT_DATA_ERROR, || {
            rust_lzma_init_impl(state, size_override, next_in, avail_in)
        })
    }
}

unsafe fn rust_lzma_decode_impl(
    state: *mut *mut c_void,
    next_in: *mut *mut u8,
    avail_in: *mut usize,
    next_out: *mut *mut u8,
    avail_out: *mut usize,
) -> i32 {
    if state.is_null() {
        return RESULT_DATA_ERROR;
    }
    // Preserve the legacy wrapper contract: callers may begin with Decode and
    // let it incrementally initialize the decoder from the supplied header.
    if unsafe { (*state).is_null() }
        && unsafe { rust_lzma_init_impl(state, 0, next_in, avail_in) } != RESULT_OK
    {
        return RESULT_DATA_ERROR;
    }
    let decoder = unsafe { &mut *((*state).cast::<LzmaState>()) };
    if decoder.decoder.is_none() {
        let input_len = unsafe { *avail_in };
        let input_ptr = unsafe { *next_in };
        if input_len != 0 && input_ptr.is_null() {
            return RESULT_DATA_ERROR;
        }
        let mut input = if input_len == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(input_ptr, input_len) }
        };
        let before = input.len();
        if decoder.consume_header(&mut input).is_err() {
            return RESULT_DATA_ERROR;
        }
        let consumed = before - input.len();
        unsafe {
            if consumed != 0 {
                *next_in = (*next_in).add(consumed);
            }
            *avail_in -= consumed;
        }
        if decoder.decoder.is_none() {
            return RESULT_OK;
        }
    }

    let Some((input, output)) = (unsafe { buffer_pair(next_in, avail_in, next_out, avail_out) })
    else {
        return RESULT_DATA_ERROR;
    };
    // The legacy interface has no explicit finish operation. Its callers drain
    // the decoder with an empty input buffer after supplying the complete
    // compressed member, so translate that state to the sans-I/O finish action.
    let action = if input.is_empty() {
        Action::Finish
    } else {
        Action::Run
    };
    let Some(stream) = decoder.decoder.as_mut() else {
        return RESULT_DATA_ERROR;
    };
    match stream.process(input, output, action) {
        Ok(result) => {
            if !unsafe {
                advance_pair(
                    next_in,
                    avail_in,
                    result.bytes_consumed,
                    next_out,
                    avail_out,
                    result.bytes_produced,
                )
            } {
                return RESULT_DATA_ERROR;
            }
            if result.status == Status::StreamEnd {
                STREAM_END
            } else {
                RESULT_OK
            }
        }
        Err(error) => {
            debug!("Rust LZMA decoder error: {error}");
            RESULT_DATA_ERROR
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_lzma_decode(
    state: *mut *mut c_void,
    next_in: *mut *mut u8,
    avail_in: *mut usize,
    next_out: *mut *mut u8,
    avail_out: *mut usize,
) -> i32 {
    unsafe {
        ffi_guard(state, RESULT_DATA_ERROR, || {
            rust_lzma_decode_impl(state, next_in, avail_in, next_out, avail_out)
        })
    }
}

unsafe fn rust_lzma_shutdown_impl(state: *mut *mut c_void) {
    if state.is_null() || unsafe { (*state).is_null() } {
        return;
    }
    unsafe { invalidate_state(state) };
}

#[no_mangle]
pub unsafe extern "C" fn rust_lzma_shutdown(state: *mut *mut c_void) {
    unsafe {
        ffi_guard(state, (), || rust_lzma_shutdown_impl(state));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LZMA_HELLO: &[u8] = &[
        93, 0, 0, 128, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 36, 25, 73, 152, 111, 22, 2,
        140, 232, 230, 91, 177, 71, 198, 206, 183, 99, 255, 255, 60, 172, 0, 0,
    ];

    unsafe fn decode_lzma_chunks(input: &[u8], size_override: u64) -> Vec<u8> {
        let mut state = ptr::null_mut();
        let mut init_input = ptr::null_mut();
        let mut init_size = 0;
        assert_eq!(
            unsafe { rust_lzma_init(&mut state, size_override, &mut init_input, &mut init_size,) },
            RESULT_OK
        );

        let mut result = Vec::new();
        let mut position = 0;
        loop {
            let end = (position + 20).min(input.len());
            let mut next_in = if position == input.len() {
                ptr::null_mut()
            } else {
                input[position..end].as_ptr().cast_mut()
            };
            let mut avail_in = end - position;
            let mut output = [0u8; 2];
            let mut next_out = output.as_mut_ptr();
            let mut avail_out = output.len();
            let status = unsafe {
                rust_lzma_decode(
                    &mut state,
                    &mut next_in,
                    &mut avail_in,
                    &mut next_out,
                    &mut avail_out,
                )
            };
            position = end - avail_in;
            result.extend_from_slice(&output[..output.len() - avail_out]);
            assert_ne!(status, RESULT_DATA_ERROR);
            if status == STREAM_END {
                break;
            }
        }
        unsafe { rust_lzma_shutdown(&mut state) };
        result
    }

    #[test]
    fn lzma_file_is_decoded_in_bounded_chunks() {
        assert_eq!(
            unsafe { decode_lzma_chunks(LZMA_HELLO, 0) },
            b"Hello, world!"
        );
    }

    #[test]
    fn raw_lzma_is_decoded_in_bounded_chunks_and_drained_at_eof() {
        let raw = [&LZMA_HELLO[..5], &LZMA_HELLO[13..]].concat();
        assert_eq!(unsafe { decode_lzma_chunks(&raw, 13) }, b"Hello, world!");
    }

    #[test]
    fn lzma_rejects_untrusted_large_dictionary_before_allocation() {
        let mut state = ptr::null_mut();
        let mut header = [93, 0, 0, 0, 0x10];
        let mut next_in = header.as_mut_ptr();
        let mut avail_in = header.len();
        assert_eq!(
            unsafe { rust_lzma_init(&mut state, u64::MAX, &mut next_in, &mut avail_in) },
            RESULT_DATA_ERROR
        );
        unsafe { rust_lzma_shutdown(&mut state) };
    }

    #[test]
    fn ffi_panic_is_contained_and_invalidates_state() {
        let mut state = Box::into_raw(Box::new(LzmaState::new(0))).cast();
        let result = unsafe { ffi_guard(&mut state, RESULT_DATA_ERROR, || panic!("test panic")) };
        assert_eq!(result, RESULT_DATA_ERROR);
        assert!(state.is_null());
    }

    #[test]
    fn invalid_internal_header_state_returns_data_error() {
        let decoder = LzmaState {
            header: Vec::new(),
            header_len: 0,
            size_override: None,
            decoder: None,
        };
        let mut state = Box::into_raw(Box::new(decoder)).cast();
        let mut next_in = ptr::null_mut();
        let mut avail_in = 0;
        let mut output = [0u8; 1];
        let mut next_out = output.as_mut_ptr();
        let mut avail_out = output.len();

        assert_eq!(
            unsafe {
                rust_lzma_decode(
                    &mut state,
                    &mut next_in,
                    &mut avail_in,
                    &mut next_out,
                    &mut avail_out,
                )
            },
            RESULT_DATA_ERROR
        );
        unsafe { rust_lzma_shutdown(&mut state) };
        assert!(state.is_null());
    }
}
