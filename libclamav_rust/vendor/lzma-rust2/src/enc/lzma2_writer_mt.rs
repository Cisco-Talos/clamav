use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
        mpsc::SyncSender,
    },
};

use super::Lzma2Writer;
use crate::{
    AutoFinish, AutoFinisher, ByteWriter, Lzma2Options, error_invalid_input, set_error,
    work_pool::{WorkPool, WorkPoolConfig},
    work_queue::WorkerHandle,
};

/// A work unit for a worker thread.
#[derive(Debug, Clone)]
struct WorkUnit {
    data: Vec<u8>,
    options: Lzma2Options,
}

/// A multi-threaded LZMA2 compressor.
pub struct Lzma2WriterMt<W: Write> {
    inner: W,
    options: Lzma2Options,
    chunk_size: usize,
    current_work_unit: Vec<u8>,
    work_pool: WorkPool<WorkUnit, Vec<u8>>,
}

impl<W: Write> Lzma2WriterMt<W> {
    /// Creates a new multi-threaded LZMA2 writer.
    ///
    /// - `inner`: The writer to write compressed data to.
    /// - `options`: The LZMA2 options used for compressing. Chunk size must be set when using the
    ///   multi-threaded encoder. If you need just one chunk, then use the single-threaded encoder.
    /// - `num_workers`: The maximum number of worker threads for compression.
    ///   Currently capped at 256 Threads.
    pub fn new(inner: W, options: Lzma2Options, num_workers: u32) -> crate::Result<Self> {
        let chunk_size = match options.chunk_size {
            None => return Err(error_invalid_input("chunk size must be set")),
            Some(chunk_size) => chunk_size.get().max(options.lzma_options.dict_size as u64),
        };

        let chunk_size = usize::try_from(chunk_size)
            .map_err(|_| error_invalid_input("chunk size bigger than usize"))?;

        // We don't know how many work units we'll have ahead of time.
        let num_work = u64::MAX;

        Ok(Self {
            inner,
            options,
            chunk_size,
            current_work_unit: Vec::with_capacity(chunk_size),
            work_pool: WorkPool::new(
                WorkPoolConfig::new(num_workers, num_work),
                worker_thread_logic,
            ),
        })
    }

    /// Sends the current work unit to the workers.
    fn send_work_unit(&mut self) -> io::Result<()> {
        if self.current_work_unit.is_empty() {
            return Ok(());
        }

        self.drain_available_results()?;

        let work_data = core::mem::take(&mut self.current_work_unit);
        let mut single_chunk_options = self.options.clone();
        single_chunk_options.chunk_size = None;
        single_chunk_options.lzma_options.preset_dict = None;

        let mut work_data_opt = Some(work_data);

        self.work_pool.dispatch_next_work(&mut |_seq| {
            let data = work_data_opt.take().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "work already provided")
            })?;
            Ok(WorkUnit {
                data,
                options: single_chunk_options.clone(),
            })
        })?;

        self.drain_available_results()?;

        Ok(())
    }

    /// Drains all currently available results from the work pool and writes them.
    fn drain_available_results(&mut self) -> io::Result<()> {
        while let Some(compressed_data) = self.work_pool.try_get_result()? {
            self.inner.write_all(&compressed_data)?;
        }
        Ok(())
    }

    /// Returns a wrapper around `self` that will finish the stream on drop.
    pub fn auto_finish(self) -> AutoFinisher<Self> {
        AutoFinisher(Some(self))
    }

    /// Consume the Lzma2WriterMt and return the inner writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Finishes the compression and returns the underlying writer.
    pub fn finish(mut self) -> io::Result<W> {
        if !self.current_work_unit.is_empty() {
            self.send_work_unit()?;
        }

        // If no data was provided to compress, write an empty LZMA2 stream.
        if self.work_pool.next_index_to_dispatch() == 0 {
            self.inner.write_u8(0x00)?;
            self.inner.flush()?;

            return Ok(self.inner);
        }

        // Mark the WorkPool as finished so it knows no more work is coming.
        self.work_pool.finish();

        // Wait for all remaining work to complete.
        while let Some(compressed_data) = self.work_pool.get_result(|_| {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no more work to dispatch",
            ))
        })? {
            self.inner.write_all(&compressed_data)?;
        }

        self.inner.write_u8(0x00)?;
        self.inner.flush()?;

        Ok(self.inner)
    }
}

/// The logic for a single worker thread.
fn worker_thread_logic(
    worker_handle: WorkerHandle<(u64, WorkUnit)>,
    result_tx: SyncSender<(u64, Vec<u8>)>,
    shutdown_flag: Arc<AtomicBool>,
    error_store: Arc<Mutex<Option<io::Error>>>,
    active_workers: Arc<AtomicU32>,
) {
    while !shutdown_flag.load(Ordering::Acquire) {
        let (index, work_unit) = match worker_handle.steal() {
            Some(work) => {
                active_workers.fetch_add(1, Ordering::Release);
                work
            }
            None => {
                // No more work available and queue is closed.
                break;
            }
        };

        let mut compressed_buffer = Vec::new();

        let mut writer = Lzma2Writer::new(&mut compressed_buffer, work_unit.options);

        let result = match writer.write_all(&work_unit.data) {
            Ok(_) => match writer.flush() {
                Ok(_) => compressed_buffer,
                Err(error) => {
                    active_workers.fetch_sub(1, Ordering::Release);
                    set_error(error, &error_store, &shutdown_flag);
                    return;
                }
            },
            Err(error) => {
                active_workers.fetch_sub(1, Ordering::Release);
                set_error(error, &error_store, &shutdown_flag);
                return;
            }
        };

        if result_tx.send((index, result)).is_err() {
            active_workers.fetch_sub(1, Ordering::Release);
            return;
        }

        active_workers.fetch_sub(1, Ordering::Release);
    }
}

impl<W: Write> Write for Lzma2WriterMt<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut total_written = 0;
        let mut remaining_buf = buf;

        while !remaining_buf.is_empty() {
            let chunk_remaining = self.chunk_size.saturating_sub(self.current_work_unit.len());
            let to_write = remaining_buf.len().min(chunk_remaining);

            if to_write > 0 {
                self.current_work_unit
                    .extend_from_slice(&remaining_buf[..to_write]);
                total_written += to_write;
                remaining_buf = &remaining_buf[to_write..];
            }

            if self.current_work_unit.len() >= self.chunk_size {
                self.send_work_unit()?;
            }

            self.drain_available_results()?;
        }

        Ok(total_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.current_work_unit.is_empty() {
            self.send_work_unit()?;
        }

        // Wait for all pending work to complete and write the results.
        while let Some(compressed_data) = self.work_pool.try_get_result()? {
            self.inner.write_all(&compressed_data)?;
        }

        self.inner.flush()
    }
}

impl<W: Write> AutoFinish for Lzma2WriterMt<W> {
    fn finish_ignore_error(self) {
        let _ = self.finish();
    }
}
